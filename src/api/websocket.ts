import { SocketStream } from '@fastify/websocket';
import { FastifyRequest } from 'fastify';
import { createChildLogger } from '../lib/logger.js';
import { EventEmitter } from 'events';

const logger = createChildLogger('websocket');

// Global event bus for audit events
export const auditEventBus = new EventEmitter();

// Connected clients by audit ID
const clients = new Map<string, Set<SocketStream>>();
const allClients = new Set<SocketStream>();

export function websocketHandler(connection: SocketStream, request: FastifyRequest) {
  const clientId = Math.random().toString(36).slice(2);
  logger.info({ clientId }, 'WebSocket client connected');

  allClients.add(connection);

  connection.socket.on('message', (message: Buffer) => {
    try {
      const data = JSON.parse(message.toString());
      
      switch (data.type) {
        case 'subscribe':
          // Subscribe to specific audit updates
          if (data.auditId) {
            if (!clients.has(data.auditId)) {
              clients.set(data.auditId, new Set());
            }
            clients.get(data.auditId)!.add(connection);
            logger.info({ clientId, auditId: data.auditId }, 'Client subscribed to audit');
          }
          break;
          
        case 'unsubscribe':
          // Unsubscribe from audit updates
          if (data.auditId && clients.has(data.auditId)) {
            clients.get(data.auditId)!.delete(connection);
          }
          break;
          
        case 'ping':
          connection.socket.send(JSON.stringify({ type: 'pong' }));
          break;
      }
    } catch (error) {
      logger.error({ error, clientId }, 'Failed to parse WebSocket message');
    }
  });

  connection.socket.on('close', () => {
    logger.info({ clientId }, 'WebSocket client disconnected');
    allClients.delete(connection);
    
    // Remove from all audit subscriptions
    clients.forEach((subscribers) => {
      subscribers.delete(connection);
    });
  });

  connection.socket.on('error', (error) => {
    logger.error({ error, clientId }, 'WebSocket error');
  });
}

// Broadcast to all clients subscribed to an audit
export function broadcastToAudit(auditId: string, event: object) {
  const subscribers = clients.get(auditId);
  if (subscribers) {
    const message = JSON.stringify(event);
    subscribers.forEach((client) => {
      try {
        client.socket.send(message);
      } catch (error) {
        logger.error({ error, auditId }, 'Failed to send WebSocket message');
      }
    });
  }
}

// Broadcast to all connected clients
export function broadcastToAll(event: object) {
  const message = JSON.stringify(event);
  allClients.forEach((client) => {
    try {
      client.socket.send(message);
    } catch (error) {
      logger.error({ error }, 'Failed to broadcast message');
    }
  });
}

// Helper functions for specific events
export function emitAuditProgress(auditId: string, stage: string, progress: number, message?: string) {
  const event = {
    type: 'audit:progress',
    auditId,
    timestamp: new Date().toISOString(),
    data: { stage, progress, message },
  };
  broadcastToAudit(auditId, event);
  auditEventBus.emit('audit:progress', event);
}

export function emitAuditFinding(auditId: string, finding: object) {
  const event = {
    type: 'audit:finding',
    auditId,
    timestamp: new Date().toISOString(),
    data: finding,
  };
  broadcastToAudit(auditId, event);
  auditEventBus.emit('audit:finding', event);
}

export function emitAuditCompleted(auditId: string, summary: object) {
  const event = {
    type: 'audit:completed',
    auditId,
    timestamp: new Date().toISOString(),
    data: summary,
  };
  broadcastToAudit(auditId, event);
  broadcastToAll(event); // Notify all clients about completed audit
  auditEventBus.emit('audit:completed', event);
}

export function emitAuditFailed(auditId: string, error: string) {
  const event = {
    type: 'audit:failed',
    auditId,
    timestamp: new Date().toISOString(),
    data: { error },
  };
  broadcastToAudit(auditId, event);
  auditEventBus.emit('audit:failed', event);
}

export function emitPocResult(auditId: string, vulnerabilityId: string, result: object) {
  const event = {
    type: 'poc:completed',
    auditId,
    timestamp: new Date().toISOString(),
    data: { vulnerabilityId, ...result },
  };
  broadcastToAudit(auditId, event);
  auditEventBus.emit('poc:completed', event);
}

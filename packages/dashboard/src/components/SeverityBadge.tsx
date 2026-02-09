interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md' | 'lg';
}

const severityConfig: Record<string, { bg: string; text: string; emoji: string }> = {
  CRITICAL: { bg: 'bg-red-100', text: 'text-red-800', emoji: '🔴' },
  HIGH: { bg: 'bg-orange-100', text: 'text-orange-800', emoji: '🟠' },
  MEDIUM: { bg: 'bg-yellow-100', text: 'text-yellow-800', emoji: '🟡' },
  LOW: { bg: 'bg-green-100', text: 'text-green-800', emoji: '🟢' },
  INFO: { bg: 'bg-blue-100', text: 'text-blue-800', emoji: 'ℹ️' },
};

const sizeClasses = {
  sm: 'text-xs px-2 py-0.5',
  md: 'text-sm px-2.5 py-1',
  lg: 'text-base px-3 py-1.5',
};

export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const config = severityConfig[severity] || severityConfig.INFO;
  
  return (
    <span className={`inline-flex items-center gap-1 rounded-full font-medium ${config.bg} ${config.text} ${sizeClasses[size]}`}>
      <span>{config.emoji}</span>
      <span>{severity}</span>
    </span>
  );
}

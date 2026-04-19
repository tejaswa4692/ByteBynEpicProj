import { cn } from '@/lib/utils'

const STYLES = {
  CRITICAL: 'bg-red-500/15 text-red-400 border border-red-500/30',
  HIGH:     'bg-orange-500/15 text-orange-400 border border-orange-500/30',
  MEDIUM:   'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  LOW:      'bg-blue-500/15 text-blue-400 border border-blue-500/30',
}

export default function SeverityBadge({ severity, className }) {
  return (
    <span className={cn(
      'inline-flex items-center px-2 py-0.5 rounded-md text-xs font-bold tracking-wide',
      STYLES[severity] ?? 'bg-secondary text-muted-foreground border border-border',
      className
    )}>
      {severity ?? 'N/A'}
    </span>
  )
}

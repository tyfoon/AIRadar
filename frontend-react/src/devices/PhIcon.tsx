// Renders a Phosphor duotone icon from its class name (e.g. 'ph-laptop')
interface Props {
  icon: string;
  className?: string;
}

export default function PhIcon({ icon, className = 'text-xl' }: Props) {
  return <i className={`ph-duotone ${icon} ${className}`} />;
}

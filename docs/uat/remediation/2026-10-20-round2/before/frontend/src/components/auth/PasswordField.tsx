'use client';
import { useId, useState, type InputHTMLAttributes } from 'react';
import { Eye, EyeOff, LockKeyhole } from 'lucide-react';
import { Input } from '@/components/ui/Input';

export function PasswordField({ label, ...props }: InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const [visible, setVisible] = useState(false);
  const id = useId();
  return <div className="space-y-1.5"><label htmlFor={id} className="text-sm font-medium text-hcl-navy">{label}</label><div className="relative"><LockKeyhole aria-hidden="true" className="pointer-events-none absolute left-3 top-4 h-4 w-4 text-hcl-muted" /><Input {...props} id={id} type={visible ? 'text' : 'password'} className="h-12 pl-10 pr-12" /><button type="button" aria-label={`${visible ? 'Hide' : 'Show'} ${label.toLowerCase()}`} aria-pressed={visible} onClick={() => setVisible(v => !v)} className="absolute right-1 top-1 flex h-10 w-10 items-center justify-center rounded-md text-hcl-muted hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary">{visible ? <EyeOff size={18} /> : <Eye size={18} />}</button></div></div>;
}

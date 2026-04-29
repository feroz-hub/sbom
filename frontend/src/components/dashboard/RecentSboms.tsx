import Link from 'next/link';
import { FileText, ArrowRight, ListTree } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/Card';
import { Spinner } from '@/components/ui/Spinner';
import { formatDate } from '@/lib/utils';
import type { RecentSbom } from '@/types';

interface RecentSbomsProps {
  sboms: RecentSbom[] | undefined;
  isLoading: boolean;
}

export function RecentSboms({ sboms, isLoading }: RecentSbomsProps) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Recent SBOMs</CardTitle>
        <Link
          href="/sboms"
          className="flex items-center gap-1 text-xs font-medium text-primary transition-colors hover:text-hcl-dark hover:underline"
        >
          View all <ArrowRight className="h-3 w-3" />
        </Link>
      </CardHeader>
      <CardContent className="p-0">
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <Spinner />
          </div>
        ) : !sboms?.length ? (
          <div className="text-center py-10 px-4 space-y-3">
            <p className="text-hcl-muted text-sm">No SBOMs uploaded yet.</p>
            <Link
              href="/sboms"
              className="inline-flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-hcl-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hcl-blue/50"
            >
              <FileText className="h-4 w-4" aria-hidden />
              Go to SBOMs to upload
            </Link>
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {sboms.map((sbom) => (
              <li key={sbom.id} className="flex items-stretch">
                <Link
                  href={`/sboms/${sbom.id}`}
                  className="flex min-w-0 flex-1 items-center gap-3 px-4 py-3.5 sm:px-6 hover:bg-hcl-light/60 transition-colors group"
                >
                  <div className="flex-shrink-0 w-8 h-8 bg-hcl-light rounded-lg flex items-center justify-center">
                    <FileText className="h-4 w-4 text-hcl-blue" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-hcl-navy truncate group-hover:text-hcl-blue transition-colors">
                      {sbom.sbom_name}
                    </p>
                    <p className="text-xs text-hcl-muted">{formatDate(sbom.created_on)}</p>
                  </div>
                  <ArrowRight className="h-4 w-4 text-hcl-border group-hover:text-hcl-blue transition-colors flex-shrink-0 hidden sm:block" />
                </Link>
                <Link
                  href={`/analysis?sbom=${sbom.id}&tab=runs`}
                  className="flex shrink-0 items-center gap-1.5 border-l border-border px-3 py-3.5 text-xs font-medium text-primary hover:bg-hcl-light/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-hcl-blue/40 sm:px-4"
                  title={`Analysis runs filtered for ${sbom.sbom_name}`}
                >
                  <ListTree className="h-4 w-4 shrink-0" aria-hidden />
                  <span className="hidden sm:inline">Runs</span>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}

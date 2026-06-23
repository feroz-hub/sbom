'use client';

import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { ResponsiveContainer, Tooltip, Treemap, type TooltipProps } from 'recharts';
import { Surface, SurfaceContent, SurfaceHeader } from '@/components/ui/Surface';
import { Spinner } from '@/components/ui/Spinner';
import { EmptyState } from '@/components/ui/EmptyState';
import { getDashboardRiskMap } from '@/lib/api';
import type { RiskMapItem } from '@/types';

/**
 * Portfolio risk map — treemap of analysed SBOMs.
 *
 * Cell area = finding count in that SBOM's latest successful run; colour =
 * the worst severity tier present (both directly observable — no composite
 * score, per the retired-Risk-Index decision in docs/risk-index.md).
 * Clicking a cell opens the SBOM detail page.
 */

const DOMINANT_COLOR: Record<string, string> = {
  critical: '#C0392B',
  high: '#D4680A',
  medium: '#B8860B',
  low: '#0067B1',
  unknown: '#5B7083',
  none: '#1E8449',
};

interface TreemapDatum extends RiskMapItem {
  size: number;
}

interface CellProps {
  x?: number;
  y?: number;
  width?: number;
  height?: number;
  // Recharts spreads the datum onto the content props.
  [key: string]: unknown;
}

function MapCell(props: CellProps) {
  const { x = 0, y = 0, width = 0, height = 0 } = props;
  const datum = props as unknown as TreemapDatum;
  if (width <= 0 || height <= 0) return null;
  const fill = DOMINANT_COLOR[datum.dominant] ?? DOMINANT_COLOR.unknown;
  const showName = width > 70 && height > 34;
  const showCount = width > 70 && height > 52;
  return (
    <g style={{ cursor: 'pointer' }}>
      <rect
        x={x}
        y={y}
        width={width}
        height={height}
        rx={4}
        fill={fill}
        fillOpacity={0.85}
        stroke="var(--color-surface, #fff)"
        strokeWidth={2}
      />
      {showName && (
        <text x={x + 8} y={y + 18} fill="#fff" fontSize={11} fontWeight={600}>
          {String(datum.name ?? '').slice(0, Math.max(4, Math.floor(width / 7)))}
        </text>
      )}
      {showCount && (
        <text x={x + 8} y={y + 34} fill="#fff" fontSize={10} fillOpacity={0.9}>
          {Number(datum.findings_total ?? 0).toLocaleString()} findings
        </text>
      )}
    </g>
  );
}

function MapTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null;
  const d = payload[0]?.payload as TreemapDatum | undefined;
  if (!d) return null;
  return (
    <div className="rounded-lg border border-border-subtle bg-surface px-3 py-2 text-xs shadow-elev-3">
      <div className="font-semibold text-hcl-navy">{d.name}</div>
      {d.project && <div className="text-[10px] text-hcl-muted">{d.project}</div>}
      <div className="mt-1 grid grid-cols-2 gap-x-3 font-metric tabular-nums text-hcl-navy">
        <span className="text-[#C0392B]">C {d.critical}</span>
        <span className="text-[#D4680A]">H {d.high}</span>
        <span className="text-[#B8860B]">M {d.medium}</span>
        <span className="text-[#0067B1]">L {d.low}</span>
      </div>
      <div className="mt-1 text-[10px] uppercase tracking-wider text-hcl-muted">
        Click to open SBOM
      </div>
    </div>
  );
}

export interface PortfolioRiskMapProps {
  riskMap?: any;
  isLoading?: boolean;
}

export function PortfolioRiskMap({ riskMap, isLoading: propsIsLoading }: PortfolioRiskMapProps = {}) {
  const router = useRouter();
  const hasProps = riskMap !== undefined;

  const queryResult = useQuery({
    queryKey: ['dashboard-risk-map'],
    queryFn: ({ signal }) => getDashboardRiskMap(signal),
    enabled: !hasProps,
  });

  const apiData = hasProps ? riskMap : queryResult.data;
  const isLoading = hasProps ? !!propsIsLoading : queryResult.isLoading;

  const items = apiData?.items ?? [];
  const data: TreemapDatum[] = items
    .filter((i: any) => i.findings_total > 0)
    .map((i: any) => ({ ...i, size: i.findings_total }));
  const clean = items.length - data.length;

  return (
    <Surface variant="elevated">
      <SurfaceHeader>
        <div>
          <h3 className="text-base font-semibold text-hcl-navy">Portfolio risk map</h3>
          <p className="mt-0.5 text-xs text-hcl-muted">
            Cell size = findings in latest run · colour = worst severity present
            {clean > 0 && ` · ${clean} clean SBOM${clean === 1 ? '' : 's'} not shown`}
          </p>
        </div>
      </SurfaceHeader>
      <SurfaceContent>
        {isLoading ? (
          <div className="flex h-64 items-center justify-center">
            <Spinner />
          </div>
        ) : data.length === 0 ? (
          <EmptyState
            illustration="all-clear"
            title="Portfolio is clean"
            description="No analysed SBOM currently carries findings."
            compact
          />
        ) : (
          <ResponsiveContainer width="100%" height={260}>
            <Treemap
              data={data}
              dataKey="size"
              nameKey="name"
              isAnimationActive={false}
              content={<MapCell />}
              onClick={(node: unknown) => {
                const d = node as Partial<TreemapDatum> | null;
                if (d?.sbom_id != null) router.push(`/sboms/${d.sbom_id}`);
              }}
            >
              <Tooltip content={<MapTooltip />} />
            </Treemap>
          </ResponsiveContainer>
        )}
      </SurfaceContent>
    </Surface>
  );
}

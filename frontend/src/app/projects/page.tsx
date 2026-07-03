'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useQuery } from '@tanstack/react-query';
import { Plus } from 'lucide-react';
import { TopBar } from '@/components/layout/TopBar';
import { Button } from '@/components/ui/Button';
import { ProjectsTable } from '@/components/projects/ProjectsTable';
import { ProjectModal } from '@/components/projects/ProjectModal';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/Card';
import { getProducts, getProjects } from '@/lib/api';
import type { Project } from '@/types';

function ProjectProducts({ project }: { project: Project }) {
  const { data, isLoading } = useQuery({
    queryKey: ['products', project.id],
    queryFn: ({ signal }) => getProducts(project.id, signal),
  });
  const products = data?.items ?? [];
  return (
    <Card>
      <CardHeader>
        <CardTitle>{project.project_name}</CardTitle>
      </CardHeader>
      <CardContent>
        {isLoading ? (
          <p className="text-sm text-hcl-muted">Loading products...</p>
        ) : products.length === 0 ? (
          <p className="text-sm text-hcl-muted">No products found for this project.</p>
        ) : (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {products.map((product) => (
              <Link
                key={product.id}
                href={`/products/${product.id}`}
                className="rounded-lg border border-hcl-border bg-surface-muted p-3 transition-colors hover:border-hcl-blue hover:bg-row-hover"
              >
                <div className="font-medium text-hcl-navy">{product.name}</div>
                <div className="mt-1 text-xs text-hcl-muted">
                  {product.sbom_count ?? 0} SBOM{product.sbom_count === 1 ? '' : 's'}
                  {product.latest_sbom_version ? ` · Latest ${product.latest_sbom_version}` : ''}
                </div>
              </Link>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default function ProjectsPage() {
  const [showCreate, setShowCreate] = useState(false);

  const { data: projects, isLoading, error } = useQuery({
    queryKey: ['projects'],
    queryFn: ({ signal }) => getProjects(signal),
  });

  return (
    <div className="flex flex-col flex-1">
      <TopBar
        title="Projects"
        action={
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" />
            New Project
          </Button>
        }
      />
      <div className="space-y-6 p-6">
        <ProjectsTable
          projects={projects}
          isLoading={isLoading}
          error={error}
        />
        {!isLoading && !error && projects?.length ? (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-hcl-navy">Products</h2>
            {projects.map((project) => (
              <ProjectProducts key={project.id} project={project} />
            ))}
          </div>
        ) : null}
      </div>

      <ProjectModal
        open={showCreate}
        onClose={() => setShowCreate(false)}
      />
    </div>
  );
}

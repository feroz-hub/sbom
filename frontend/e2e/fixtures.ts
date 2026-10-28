import { randomUUID } from 'node:crypto';
export function validSbom() {
  return {
    bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
    serialNumber: `urn:uuid:${randomUUID()}`,
    metadata: {timestamp: '2026-10-06T00:00:00Z', tools: [{vendor:'Release Test',name:'Fixture Generator',version:'1'}]},
    components: [
      {type:'application', 'bom-ref':'app', name:'release-app',version:'1.0.0',purl:'pkg:generic/release-app@1.0.0', supplier:{name:'Release Fixture'}},
      {type:'library', 'bom-ref':'beta',name:'beta',version:'2.0.0',purl:'pkg:npm/beta@2.0.0', supplier:{name:'Release Fixture'}},
    ],
    dependencies:[{ref:'app',dependsOn:['beta']}],
  };
}
export function repairableSbom() {
  const doc = validSbom();
  doc.components[1].type = ' Library ';
  doc.components.push({type:'library','bom-ref':'tool-copy',name:'tool-one',version:'1.0.0',purl:'pkg:generic/tool-one@1.0.0',supplier:{name:'Release Fixture'}});
  doc.components.push({type:'library','bom-ref':'tool-copy',name:'tool-two',version:'1.0.0',purl:'pkg:generic/tool-two@1.0.0',supplier:{name:'Release Fixture'}});
  const edge = {ref:'app',dependsOn:['pkg:npm/beta@2.0.0','pkg:npm/beta@2.0.0']};
  doc.dependencies = [edge, structuredClone(edge)];
  return doc;
}
export function partialSbom() {
  const doc = validSbom();
  doc.components[0].type = 'APPLICATION';
  doc.components[1].purl = 'not-a-purl';
  return doc;
}
export function ambiguousSbom() {
  const doc = validSbom();
  doc.components[1].purl = 'pkg:npm/library-x';
  doc.components[1].name = 'library-x';
  doc.components.push({type:'library','bom-ref':'library-x-v1',name:'library-x',version:'1.0.0',purl:'pkg:npm/library-x',supplier:{name:'Release Fixture'}});
  doc.dependencies = [{ref:'app',dependsOn:['pkg:npm/library-x']}];
  return doc;
}

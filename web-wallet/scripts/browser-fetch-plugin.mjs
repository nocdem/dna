import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const sourceHash = 'd39770ece2d303961800bdc942ef878d98d67981d2be185dfe994be2467d07a1';
const normalize = path => path.replaceAll('\\', '/');

// micro-ftch 0.3.1: select its existing browser implementation at build time.
// Keep the original module ID for dependency/license attribution. A dependency
// upgrade requires explicit source review and a new pin, never a silent rewrite.
export function browserFetchPlugin() {
  const target = normalize(require.resolve('micro-ftch'));
  return {
    name: 'nodus-extension-browser-fetch',
    enforce: 'pre',
    transform(code, id) {
      if (normalize(id) !== target) return;
      if (createHash('sha256').update(code).digest('hex') !== sourceHash) {
        this.error('Unexpected micro-ftch source hash; review the browser-branch transformation');
      }
      const ast = this.parse(code);
      const nodeFunctions = ast.body.filter(node =>
        node.type === 'FunctionDeclaration' && node.id?.name === 'fetchNode');
      const nodeFlags = ast.body.filter(node => node.type === 'VariableDeclaration' &&
        node.declarations.some(declaration => declaration.id.type === 'Identifier' && declaration.id.name === 'IS_NODE'));
      if (nodeFunctions.length !== 1 || nodeFlags.length !== 1 ||
          nodeFlags[0].kind !== 'const' || nodeFlags[0].declarations.length !== 1 ||
          !nodeFlags[0].declarations[0].init) {
        this.error('Unexpected micro-ftch AST; expected one fetchNode function and one IS_NODE constant');
      }
      const init = nodeFlags[0].declarations[0].init;
      const edits = [
        { start: nodeFunctions[0].start, end: nodeFunctions[0].end, text: '' },
        { start: init.start, end: init.end, text: 'false' },
      ].sort((a, b) => b.start - a.start);
      for (const edit of edits) {
        if (!Number.isInteger(edit.start) || !Number.isInteger(edit.end) ||
            edit.start < 0 || edit.end <= edit.start || edit.end > code.length) {
          this.error('Unexpected micro-ftch AST offsets');
        }
      }
      // Offset edits preserve fetchBrowser, fetchUrl and error classes verbatim.
      for (const edit of edits) code = code.slice(0, edit.start) + edit.text + code.slice(edit.end);
      return { code, map: null };
    },
  };
}

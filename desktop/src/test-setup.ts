import "@testing-library/jest-dom/vitest";

// jsdom has no layout engine. React Flow measures its container and nodes with these, so give it inert stand-ins.
class ResizeObserverStub { observe() {} unobserve() {} disconnect() {} }
if (!("ResizeObserver" in globalThis)) (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = ResizeObserverStub;
if (!("DOMMatrixReadOnly" in globalThis)) {
  (globalThis as unknown as { DOMMatrixReadOnly: unknown }).DOMMatrixReadOnly = class { m22 = 1; constructor(_transform?: string) {} };
}

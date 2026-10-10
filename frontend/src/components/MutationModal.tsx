import type { Mutation } from "../api/types";
import { Modal } from "./Modal";

interface MutationModalProps {
  mutations: Mutation[];
  enabled: string[];
  onChange: (enabled: string[]) => void;
  onClose: () => void;
}

/** Choose which payload mutations the fuzzer applies. */
export function MutationModal({ mutations, enabled, onChange, onClose }: MutationModalProps) {
  const toggle = (id: string) => onChange(enabled.includes(id) ? enabled.filter((m) => m !== id) : [...enabled, id]);

  return (
    <Modal
      title="Attack mutation rules"
      onClose={onClose}
      footer={
        <>
          <div className="row">
            <button className="btn btn-sm" onClick={() => onChange(mutations.map((m) => m.id))}>Enable all</button>
            <button className="btn btn-sm" onClick={() => onChange(["baseline"])}>Baseline only</button>
          </div>
          <button className="btn btn-primary" onClick={onClose}>Done ({enabled.length})</button>
        </>
      }
    >
      <p className="muted small">Mutations are deterministic rewrites of a payload. The same input always produces the same attack.</p>
      {mutations.map((mutation) => (
        <label className="check" key={mutation.id}>
          <input type="checkbox" checked={enabled.includes(mutation.id)} onChange={() => toggle(mutation.id)} />
          <span>
            <strong>{mutation.label}</strong>
            <div className="small muted">{mutation.description}</div>
          </span>
        </label>
      ))}
    </Modal>
  );
}

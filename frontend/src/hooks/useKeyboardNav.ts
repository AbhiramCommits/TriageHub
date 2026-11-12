import { useEffect, useRef, useState } from "react";

export interface KeyboardNavOptions {
  count: number;
  onToggle: (index: number) => void;
  onAccept: (index: number) => void;
  onMute: (index: number) => void;
  onOpen: (index: number) => void;
  onClose: () => void;
  onHelp: () => void;
}

function isEditable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return (
    tag === "input" ||
    tag === "textarea" ||
    tag === "select" ||
    target.isContentEditable
  );
}

export function useKeyboardNav(options: KeyboardNavOptions) {
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const optionsRef = useRef(options);
  optionsRef.current = options;

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      const current = optionsRef.current;
      if (event.key === "Escape") {
        current.onClose();
        return;
      }
      if (isEditable(event.target) || event.metaKey || event.ctrlKey || event.altKey) return;
      if (current.count === 0 && event.key !== "?") return;

      switch (event.key) {
        case "j": {
          event.preventDefault();
          setFocusedIndex((index) => Math.min(current.count - 1, index + 1));
          break;
        }
        case "k": {
          event.preventDefault();
          setFocusedIndex((index) => Math.max(0, index - 1));
          break;
        }
        case "x": {
          event.preventDefault();
          setFocusedIndex((index) => {
            const target = index < 0 ? 0 : index;
            current.onToggle(target);
            return target;
          });
          break;
        }
        case "a": {
          event.preventDefault();
          setFocusedIndex((index) => {
            current.onAccept(Math.max(0, index));
            return index;
          });
          break;
        }
        case "m": {
          event.preventDefault();
          setFocusedIndex((index) => {
            current.onMute(Math.max(0, index));
            return index;
          });
          break;
        }
        case "Enter": {
          event.preventDefault();
          setFocusedIndex((index) => {
            current.onOpen(Math.max(0, index));
            return index;
          });
          break;
        }
        case "?": {
          event.preventDefault();
          current.onHelp();
          break;
        }
        default:
          break;
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  useEffect(() => {
    if (focusedIndex >= options.count) {
      setFocusedIndex(options.count - 1);
    }
  }, [options.count, focusedIndex]);

  return { focusedIndex, setFocusedIndex };
}

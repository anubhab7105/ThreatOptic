import { create } from 'zustand';


type SceneState = {
  progress: number;
  setProgress: (p: number) => void;
};

export const useSceneStore = create<SceneState>((set) => ({
  progress: 0,
  setProgress: (p) => set({ progress: Math.min(1, Math.max(0, p)) }),
}));

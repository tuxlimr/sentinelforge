import { Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { Evaluation } from "./pages/Evaluation";
import { ExploitLab } from "./pages/ExploitLab";
import { Findings } from "./pages/Findings";
import { Regressions } from "./pages/Regressions";
import { Scans } from "./pages/Scans";
import { SettingsPage } from "./pages/SettingsPage";

export function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Scans />} />
        <Route path="findings" element={<Findings />} />
        <Route path="regressions" element={<Regressions />} />
        <Route path="evaluation" element={<Evaluation />} />
        <Route path="lab" element={<ExploitLab />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  );
}

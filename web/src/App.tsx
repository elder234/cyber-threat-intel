import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useAuth } from './lib/auth';
import { LiveProvider } from './lib/live';
import { Shell } from './components/Shell';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Spinner } from './components/primitives';
import LoginPage from './pages/Login';
import DashboardPage from './pages/Dashboard';
import IocsPage from './pages/Iocs';
import CvesPage from './pages/Cves';
import RulesPage from './pages/Rules';
import AlertsPage from './pages/Alerts';
import NotificationsPage from './pages/Notifications';
import FeedsPage from './pages/Feeds';
import ScansPage from './pages/Scans';
import ContainersPage from './pages/Containers';
import MalwarePage from './pages/Malware';
import DarkwebPage from './pages/Darkweb';
import SearchPage from './pages/Search';

/** Gate that requires an authenticated session; preserves intended path. */
function RequireAuth({ children }: { children: JSX.Element }): JSX.Element {
  const { status } = useAuth();
  const location = useLocation();
  if (status === 'loading') {
    return (
      <div className="grid h-full place-items-center">
        <Spinner label="Establishing session" />
      </div>
    );
  }
  if (status === 'anon') {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  return children;
}

/**
 * The routed pages, wrapped in an error boundary that lives *inside* Shell so a
 * page crash leaves the nav usable. Keyed on pathname so navigating away from a
 * broken view clears the error automatically.
 */
function RoutedPages(): JSX.Element {
  const { pathname } = useLocation();
  return (
    <ErrorBoundary resetKey={pathname}>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/iocs" element={<IocsPage />} />
        <Route path="/cves" element={<CvesPage />} />
        <Route path="/rules" element={<RulesPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/notifications" element={<NotificationsPage />} />
        <Route path="/feeds" element={<FeedsPage />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/containers" element={<ContainersPage />} />
        <Route path="/malware" element={<MalwarePage />} />
        <Route path="/darkweb" element={<DarkwebPage />} />
        <Route path="/search" element={<SearchPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </ErrorBoundary>
  );
}

export default function App(): JSX.Element {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/*"
        element={
          <RequireAuth>
            <LiveProvider>
              <Shell>
                <RoutedPages />
              </Shell>
            </LiveProvider>
          </RequireAuth>
        }
      />
    </Routes>
  );
}

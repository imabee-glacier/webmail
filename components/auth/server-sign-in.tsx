"use client";

import { useEffect, useRef, useState } from "react";
import { useTranslations } from "next-intl";
import { useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { AlertCircle, KeyRound, Loader2 } from "@/components/icons";
import { useConfig } from "@/hooks/use-config";
import { useThemeStore } from "@/stores/theme-store";
import { startServerSignIn, consumeSignedOut } from "@/stores/auth-store";
import { withBasePath } from "@/lib/browser-navigation";
import { useDocumentTitle } from "@/hooks/use-document-title";

/**
 * The sign-in page when sign-in is server-held. There is no form: the mail
 * server owns sign-in, passkeys included, on its own origin. This page is the
 * moment between - it hands off at once, and it is where a sign-in that went
 * wrong comes back to, with one clear way forward.
 */
const ERRORS = ["cancelled", "expired", "unavailable", "failed"] as const;
type SignInError = (typeof ERRORS)[number];

// Read once per page load: React may run state initialisers twice, and this one consumes.
let signedOutOnLoad: boolean | null = null;
function arrivedSignedOut(): boolean {
  signedOutOnLoad ??= consumeSignedOut();
  return signedOutOnLoad;
}

function readError(value: string | null): SignInError | null {
  return value && (ERRORS as readonly string[]).includes(value) ? (value as SignInError) : null;
}

export function ServerSignIn() {
  const t = useTranslations("login.server_signin");
  const params = useSearchParams();
  const { appName, loginLogoLightUrl, loginLogoDarkUrl } = useConfig();
  const resolvedTheme = useThemeStore((s) => s.resolvedTheme);
  const [error] = useState<SignInError | null>(() => readError(params.get("signin_error")));
  // A deliberate sign-out lands here: stay, rather than signing straight back in.
  const [signedOut] = useState(arrivedSignedOut);
  const [leaving, setLeaving] = useState(false);
  const started = useRef(false);

  useDocumentTitle(t("title", { app: appName }));

  const go = (options?: { prompt?: "login" }) => {
    setLeaving(true);
    startServerSignIn(options);
  };

  useEffect(() => {
    if (started.current || error || signedOut) return;
    started.current = true;
    go();
    // Runs once, on arrival.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const logo = resolvedTheme === "dark" ? loginLogoDarkUrl : loginLogoLightUrl;
  const waiting = leaving || (!error && !signedOut);

  return (
    <main className="min-h-dvh flex items-center justify-center bg-background px-6">
      <div className="w-full max-w-[400px] flex flex-col items-center text-center">
        {logo ? (
          // eslint-disable-next-line @next/next/no-img-element
          <img src={withBasePath(logo)} alt="" className="h-12 w-auto mb-8 select-none" draggable={false} />
        ) : null}

        {waiting ? (
          <>
            <h1 className="text-xl font-semibold tracking-tight text-foreground">{t("redirecting_title")}</h1>
            <p className="mt-2 text-sm text-muted-foreground">{t("redirecting_body")}</p>
            <div className="mt-8 h-1 w-40 overflow-hidden rounded-full bg-muted" role="progressbar" aria-label={t("redirecting_title")}>
              <div className="h-full w-1/3 rounded-full bg-primary animate-[server-signin_1.2s_ease-in-out_infinite]" />
            </div>
            <style>{`@keyframes server-signin{0%{transform:translateX(-100%)}100%{transform:translateX(300%)}}@media (prefers-reduced-motion: reduce){[role=progressbar]>div{animation:none!important;width:100%}}`}</style>
          </>
        ) : (
          <div className="w-full rounded-2xl border border-border bg-card p-8 shadow-sm text-left">
            {error ? (
              <div className="flex items-start gap-3 mb-6" role="alert">
                <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-destructive" aria-hidden />
                <div>
                  <h1 className="text-base font-semibold text-foreground">{t(`error_${error}_title`)}</h1>
                  <p className="mt-1 text-sm text-muted-foreground">{t(`error_${error}_body`)}</p>
                </div>
              </div>
            ) : (
              <div className="mb-6">
                <h1 className="text-xl font-semibold tracking-tight text-foreground">{t("signed_out_title")}</h1>
                <p className="mt-1 text-sm text-muted-foreground">{t("signed_out_body", { app: appName })}</p>
              </div>
            )}
            <Button className="w-full h-11" onClick={() => go()} disabled={leaving}>
              {leaving ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <KeyRound className="h-4 w-4" aria-hidden />}
              <span>{t("continue")}</span>
            </Button>
            <Button variant="ghost" className="w-full h-11 mt-2" onClick={() => go({ prompt: "login" })} disabled={leaving}>
              {t("other_account")}
            </Button>
          </div>
        )}
      </div>
    </main>
  );
}

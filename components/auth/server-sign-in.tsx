"use client";

import { useState } from "react";
import { useTranslations } from "next-intl";
import { useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { AlertCircle, KeyRound, Loader2 } from "@/components/icons";
import { useConfig } from "@/hooks/use-config";
import { useThemeStore } from "@/stores/theme-store";
import { startServerSignIn, consumeSignedOut, consumeSessionExpired } from "@/stores/auth-store";
import { withBasePath } from "@/lib/browser-navigation";
import { useDocumentTitle } from "@/hooks/use-document-title";

/**
 * The sign-in page when sign-in is server-held. The mail server owns sign-in,
 * passkeys included, on its own origin; this page is where the person decides
 * to go there. It never leaves on its own: arriving here, being signed out,
 * a session ending and a sign-in going wrong all wait for a click.
 */
const ERRORS = ["cancelled", "expired", "unavailable", "failed"] as const;
type SignInError = (typeof ERRORS)[number];
type Arrival = "welcome" | "signed_out" | "session_ended";

// Read once per page load: React may run state initialisers twice, and these consume.
let arrivalOnLoad: Arrival | null = null;
function arrival(): Arrival {
  arrivalOnLoad ??= consumeSignedOut() ? "signed_out" : consumeSessionExpired() ? "session_ended" : "welcome";
  return arrivalOnLoad;
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
  const [arrivedAs] = useState(arrival);
  const [leaving, setLeaving] = useState<"continue" | "other" | null>(null);

  useDocumentTitle(t("title", { app: appName }));

  const go = (which: "continue" | "other") => {
    setLeaving(which);
    startServerSignIn(which === "other" ? { prompt: "login" } : undefined);
  };

  const logo = resolvedTheme === "dark" ? loginLogoDarkUrl : loginLogoLightUrl;
  const heading = arrivedAs === "welcome" ? t("welcome_title", { app: appName }) : t(`${arrivedAs}_title`);
  const body = arrivedAs === "welcome" ? t("welcome_body") : t(`${arrivedAs}_body`, { app: appName });

  return (
    <main className="min-h-dvh flex items-center justify-center bg-background px-6">
      <div className="w-full max-w-[400px] flex flex-col items-center">
        {logo ? (
          <img src={withBasePath(logo)} alt="" className="h-12 w-auto mb-8 select-none" draggable={false} />
        ) : null}

        <div className="w-full rounded-2xl border border-border bg-card p-8 shadow-sm">
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
              <h1 className="text-xl font-semibold tracking-tight text-foreground">{heading}</h1>
              <p className="mt-1.5 text-sm text-muted-foreground">{body}</p>
            </div>
          )}

          <Button className="w-full h-11" onClick={() => go("continue")} disabled={leaving !== null} autoFocus>
            {leaving === "continue" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : <KeyRound className="h-4 w-4" aria-hidden />}
            <span>{leaving === "continue" ? t("redirecting_title") : t("continue")}</span>
          </Button>
          <Button variant="ghost" className="w-full h-11 mt-2" onClick={() => go("other")} disabled={leaving !== null}>
            {leaving === "other" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden /> : null}
            <span>{t("other_account")}</span>
          </Button>
        </div>

        <p className="mt-6 text-xs text-muted-foreground text-center">{t("redirecting_body")}</p>
      </div>
    </main>
  );
}

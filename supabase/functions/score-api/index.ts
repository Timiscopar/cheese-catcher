import { createClient } from "npm:@supabase/supabase-js@2";
import { verifyMessage } from "npm:viem";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { ...corsHeaders, "Content-Type": "application/json" },
});
const isAddress = (value: unknown): value is `0x${string}` =>
  typeof value === "string" && /^0x[a-fA-F0-9]{40}$/.test(value);
const sha256 = async (value: string) => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
};
const createSessionToken = () => {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
};

Deno.serve(async req => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);
  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceKey) return json({ error: "Server configuration is incomplete." }, 500);
  const db = createClient(supabaseUrl, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });

  try {
    const body = await req.json();
    const action = body?.action;
    const wallet = typeof body?.wallet_address === "string" ? body.wallet_address.toLowerCase() : "";
    if (!isAddress(wallet)) return json({ error: "A valid wallet address is required." }, 400);

    if (action === "challenge") {
      const nonce = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const message = [
        "Cheese Catcher player sign-in", "",
        "Sign once to authenticate your wallet for this Cheese Catcher session.",
        "This signature does not authorize a transaction or spend funds.", "",
        `Wallet: ${wallet}`, `Nonce: ${nonce}`, `Expires: ${expiresAt}`,
      ].join("\n");
      const { error } = await db.from("score_challenges").insert({ id: nonce, wallet_address: wallet, message, expires_at: expiresAt });
      if (error) throw error;
      return json({ nonce, message, expires_at: expiresAt });
    }

    if (action === "authenticate") {
      const nonce = body?.nonce, signature = body?.signature;
      if (typeof nonce !== "string" || typeof signature !== "string") return json({ error: "The wallet sign-in request is incomplete." }, 400);
      const { data: challenge, error } = await db.from("score_challenges")
        .select("id,wallet_address,message,expires_at,consumed_at").eq("id", nonce).maybeSingle();
      if (error) throw error;
      if (!challenge || challenge.consumed_at || new Date(challenge.expires_at).getTime() < Date.now())
        return json({ error: "This sign-in request expired. Please connect again." }, 400);
      if (challenge.wallet_address.toLowerCase() !== wallet) return json({ error: "Wallet does not match the sign-in request." }, 400);
      // Wallet providers may encode the recovery value as 0/1 or 27/28.
      // Normalize it before viem verifies the personal-sign message.
      if (!/^0x[0-9a-fA-F]{130}$/.test(signature)) {
        return json({ error: "Wallet returned an invalid message signature." }, 400);
      }
      const recoveryValue = Number.parseInt(signature.slice(-2), 16);
      let normalizedRecoveryValue: number;
      if (recoveryValue === 0 || recoveryValue === 1) {
        normalizedRecoveryValue = recoveryValue + 27;
      } else if (recoveryValue === 27 || recoveryValue === 28) {
        normalizedRecoveryValue = recoveryValue;
      } else if (recoveryValue >= 35) {
        normalizedRecoveryValue = 27 + ((recoveryValue - 35) % 2);
      } else {
        return json({ error: "Wallet returned an unsupported signature recovery value. Please reconnect and try again." }, 400);
      }
      const normalizedSignature = (signature.slice(0, -2) + normalizedRecoveryValue.toString(16).padStart(2, "0")) as `0x${string}`;
      const valid = await verifyMessage({ address: wallet, message: challenge.message, signature: normalizedSignature });
      if (!valid) return json({ error: "Wallet signature could not be verified." }, 401);
      const { data: consumed, error: consumeError } = await db.from("score_challenges")
        .update({ consumed_at: new Date().toISOString() }).eq("id", nonce).is("consumed_at", null).select("id").maybeSingle();
      if (consumeError) throw consumeError;
      if (!consumed) return json({ error: "This sign-in request has already been used." }, 400);
      const sessionToken = createSessionToken();
      const tokenHash = await sha256(sessionToken);
      const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();
      const { error: sessionError } = await db.from("player_sessions").insert({ token_hash: tokenHash, wallet_address: wallet, expires_at: expiresAt });
      if (sessionError) throw sessionError;
      return json({ ok: true, wallet_address: wallet, session_token: sessionToken, expires_at: expiresAt });
    }

    if (action === "session_check" || action === "submit") {
      const sessionToken = body?.session_token;
      if (typeof sessionToken !== "string" || sessionToken.length < 40) return json({ error: "Player session is missing. Please sign in again." }, 401);
      const tokenHash = await sha256(sessionToken);
      const { data: session, error: sessionError } = await db.from("player_sessions")
        .select("token_hash,wallet_address,expires_at").eq("token_hash", tokenHash).eq("wallet_address", wallet).maybeSingle();
      if (sessionError) throw sessionError;
      if (!session || new Date(session.expires_at).getTime() < Date.now())
        return json({ error: "Your player session expired. Connect your wallet again to continue." }, 401);
      if (action === "session_check") return json({ ok: true });

      const score = body?.score;
      if (!Number.isInteger(score) || score < 0 || score > 10000) return json({ error: "Invalid score submission." }, 400);
      const { data: recent, error: recentError } = await db.from("scores").select("created_at")
        .eq("wallet_address", wallet).gte("created_at", new Date(Date.now() - 20_000).toISOString()).limit(1);
      if (recentError) throw recentError;
      if (recent?.length) return json({ error: "Please wait before submitting another score." }, 429);
      const { error: updateError } = await db.from("player_sessions").update({ last_used_at: new Date().toISOString() }).eq("token_hash", tokenHash);
      if (updateError) throw updateError;
      const { error: insertError } = await db.from("scores").insert({ wallet_address: wallet, score });
      if (insertError) throw insertError;
      return json({ ok: true, message: "Your score was saved to the global leaderboard." });
    }
    return json({ error: "Unknown action." }, 400);
  } catch (error) {
    console.error("score-api error:", error);
    return json({ error: "Score service error. Please try again." }, 500);
  }
});

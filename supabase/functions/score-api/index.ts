import { createClient } from "npm:@supabase/supabase-js@2";
import { verifyMessage } from "npm:viem";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

const isAddress = (value: unknown): value is `0x${string}` =>
  typeof value === "string" && /^0x[a-fA-F0-9]{40}$/.test(value);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed." }, 405);

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceKey) return json({ error: "Server configuration is incomplete." }, 500);

  const db = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  try {
    const body = await req.json();
    const action = body?.action;
    const wallet = typeof body?.wallet_address === "string" ? body.wallet_address.toLowerCase() : "";

    if (!isAddress(wallet)) return json({ error: "A valid wallet address is required." }, 400);

    if (action === "challenge") {
      const nonce = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000).toISOString();
      const message = [
        "Cheese Catcher score submission",
        "",
        "Sign this message to prove you control this wallet.",
        "This signature does not authorize a transaction or spend funds.",
        "",
        `Wallet: ${wallet}`,
        `Nonce: ${nonce}`,
        `Expires: ${expiresAt}`,
      ].join("\n");

      const { error } = await db.from("score_challenges").insert({
        id: nonce,
        wallet_address: wallet,
        message,
        expires_at: expiresAt,
      });
      if (error) throw error;
      return json({ nonce, message, expires_at: expiresAt });
    }

    if (action === "submit") {
      const nonce = body?.nonce;
      const signature = body?.signature;
      const score = body?.score;
      if (typeof nonce !== "string" || typeof signature !== "string" ||
          !Number.isInteger(score) || score < 0 || score > 10000) {
        return json({ error: "Invalid score submission." }, 400);
      }

      const { data: challenge, error: challengeError } = await db
        .from("score_challenges")
        .select("id,wallet_address,message,expires_at,consumed_at")
        .eq("id", nonce)
        .maybeSingle();
      if (challengeError) throw challengeError;
      if (!challenge || challenge.consumed_at || new Date(challenge.expires_at).getTime() < Date.now()) {
        return json({ error: "This signature request has expired or was already used. Try again." }, 400);
      }
      if (challenge.wallet_address.toLowerCase() !== wallet) {
        return json({ error: "Wallet does not match the signature request." }, 400);
      }

      const valid = await verifyMessage({
        address: wallet,
        message: challenge.message,
        signature: signature as `0x${string}`,
      });
      if (!valid) return json({ error: "Wallet signature could not be verified." }, 401);

      // Basic abuse control. This is not proof that the browser-generated score is fair.
      const { data: recent, error: recentError } = await db
        .from("scores")
        .select("created_at")
        .eq("wallet_address", wallet)
        .gte("created_at", new Date(Date.now() - 20_000).toISOString())
        .limit(1);
      if (recentError) throw recentError;
      if (recent?.length) return json({ error: "Please wait before submitting another score." }, 429);

      const { error: consumeError } = await db
        .from("score_challenges")
        .update({ consumed_at: new Date().toISOString() })
        .eq("id", nonce)
        .is("consumed_at", null);
      if (consumeError) throw consumeError;

      const { error: insertError } = await db.from("scores").insert({
        wallet_address: wallet,
        score,
      });
      if (insertError) throw insertError;

      return json({ ok: true, message: "Your wallet-signed community score was saved." });
    }

    return json({ error: "Unknown action." }, 400);
  } catch (error) {
    console.error("score-api error:", error);
    return json({ error: "Score service error. Please try again." }, 500);
  }
});

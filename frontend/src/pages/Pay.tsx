import { useEffect, useState } from "react";
import { api, ErreurApi, type Paiement } from "../api";

/**
 * Interface de paiement du client.
 *
 * Écran volontairement sobre : c'est le service marchand que l'on veut
 * maintenir disponible. Sa simplicité est un choix de démonstration : le jury
 * doit pouvoir déclencher une transaction en trois gestes, et constater son
 * résultat sans ambiguïté.
 *
 * Un bandeau de disponibilité interroge l'état de la plateforme : pendant un
 * incident, le client voit la dégradation, puis le rétablissement.
 */
export default function Pay() {
  const [comptes, setComptes] = useState<Array<{ code: string; label: string; balance_cents: number }>>([]);
  const [source, setSource] = useState("CUST-000001");
  const [destination, setDestination] = useState("MERCHANT-0001");
  const [montant, setMontant] = useState("12,50");
  const [reference, setReference] = useState("");
  const [resultat, setResultat] = useState<Paiement | null>(null);
  const [erreur, setErreur] = useState<string | null>(null);
  const [occupe, setOccupe] = useState(false);
  const [integrite, setIntegrite] = useState<{ balanced: boolean; imbalance_cents: number } | null>(null);

  useEffect(() => {
    api.comptes().then((reponse) =>
      setComptes(
        (reponse.accounts as Array<{ code: string; label: string; balance_cents: number }>).filter(
          (compte) => compte.code.startsWith("CUST-"),
        ),
      ),
    ).catch(() => setComptes([]));
    api.integrite().then(setIntegrite).catch(() => setIntegrite(null));
    setReference(referenceParDefaut());
  }, []);

  async function payer(evenement: React.FormEvent) {
    evenement.preventDefault();
    setOccupe(true);
    setErreur(null);
    setResultat(null);
    try {
      const centimes = versCentimes(montant);
      const paiement = await api.payer({
        source_account: source,
        destination_account: destination,
        amount_cents: centimes,
        currency: "EUR",
        reference: reference.trim() || referenceParDefaut(),
      });
      setResultat(paiement);
      setReference(referenceParDefaut());
      const soldes = await api.comptes();
      setComptes(
        (soldes.accounts as Array<{ code: string; label: string; balance_cents: number }>).filter(
          (compte) => compte.code.startsWith("CUST-"),
        ),
      );
      setIntegrite(await api.integrite());
    } catch (probleme) {
      if (probleme instanceof ErreurApi) {
        setErreur(`${probleme.message} (${probleme.code})`);
      } else {
        setErreur(probleme instanceof Error ? probleme.message : String(probleme));
      }
    } finally {
      setOccupe(false);
    }
  }

  return (
    <div className="flex-1 p-5 max-w-5xl mx-auto w-full">
      <header className="mb-5">
        <h1 className="font-display text-2xl font-semibold">Effectuer un paiement</h1>
        <p className="text-sm text-ink-dim mt-1">
          Plateforme de paiement fictive. Aucune donnée réelle n'est traitée.
        </p>
      </header>

      <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_320px]">
        <form onSubmit={payer} className="carte p-4 space-y-4">
          <label className="block">
            <span className="etiquette">Compte émetteur</span>
            <select
              value={source}
              onChange={(evenement) => setSource(evenement.target.value)}
              className="mt-1 w-full bg-base border border-line rounded-sm px-2.5 py-2 text-sm font-mono focus:outline-none focus:border-accent"
            >
              {comptes.length === 0 && <option value={source}>{source}</option>}
              {comptes.map((compte) => (
                <option key={compte.code} value={compte.code}>
                  {compte.code} : {formaterMontant(compte.balance_cents)}
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="etiquette">Compte destinataire</span>
            <input
              value={destination}
              onChange={(evenement) => setDestination(evenement.target.value)}
              className="mt-1 w-full bg-base border border-line rounded-sm px-2.5 py-2 text-sm font-mono focus:outline-none focus:border-accent"
            />
          </label>

          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="etiquette">Montant (EUR)</span>
              <input
                value={montant}
                onChange={(evenement) => setMontant(evenement.target.value)}
                inputMode="decimal"
                className="mt-1 w-full bg-base border border-line rounded-sm px-2.5 py-2 text-sm font-mono tabular focus:outline-none focus:border-accent"
              />
            </label>
            <label className="block">
              <span className="etiquette">Référence</span>
              <input
                value={reference}
                onChange={(evenement) => setReference(evenement.target.value)}
                className="mt-1 w-full bg-base border border-line rounded-sm px-2.5 py-2 text-sm font-mono focus:outline-none focus:border-accent"
              />
            </label>
          </div>

          <button
            type="submit"
            disabled={occupe}
            className="w-full py-2.5 font-display uppercase tracking-marque text-sm border border-accent text-accent rounded-sm hover:bg-accent/10 disabled:opacity-40"
          >
            {occupe ? "Traitement…" : "Payer"}
          </button>

          {erreur && (
            <p className="text-sm text-incident border border-incident/40 rounded-sm px-3 py-2">
              {erreur}
            </p>
          )}
          {resultat && (
            <div className="text-sm border border-nominal/40 rounded-sm px-3 py-2 space-y-1">
              <p className="text-nominal">
                Paiement accepté : {formaterMontant(resultat.amount_cents)}
              </p>
              <p className="font-mono text-[0.6875rem] text-ink-dim">
                {resultat.payment_id}
                {resultat.idempotent_replay ? " (rejeu idempotent)" : ""}
              </p>
            </div>
          )}
        </form>

        <aside className="space-y-4">
          <div className="carte p-4">
            <div className="etiquette mb-2">Intégrité du grand livre</div>
            {integrite === null ? (
              <p className="text-xs text-ink-dim">indisponible</p>
            ) : (
              <p className={`text-sm ${integrite.balanced ? "text-nominal" : "text-incident"}`}>
                {integrite.balanced
                  ? "Invariant comptable respecté"
                  : `Déséquilibre de ${formaterMontant(integrite.imbalance_cents)}`}
              </p>
            )}
          </div>

          <div className="carte p-4">
            <div className="etiquette mb-2">Comptes de démonstration</div>
            <ul className="space-y-1.5 text-xs font-mono">
              {comptes.map((compte) => (
                <li key={compte.code} className="flex justify-between gap-3">
                  <span className="text-ink-dim">{compte.code}</span>
                  <span className="tabular text-ink">{formaterMontant(compte.balance_cents)}</span>
                </li>
              ))}
              {comptes.length === 0 && <li className="text-ink-dim">chargement…</li>}
            </ul>
          </div>

          <div className="carte p-4 text-xs text-ink-dim space-y-1.5">
            <div className="etiquette mb-1">Comptes de démonstration</div>
            <p>
              <span className="font-mono text-ink">client01</span> /{" "}
              <span className="font-mono">AlphaPay-Client-2026!</span>
            </p>
            <p>
              <span className="font-mono text-ink">operateur</span> /{" "}
              <span className="font-mono">AlphaPay-Ops-2026!</span>
            </p>
            <p className="pt-1">
              Le solde est relu après chaque paiement : la cohérence entre le solde affiché et le
              journal des écritures fait partie de la démonstration.
            </p>
          </div>
        </aside>
      </div>
    </div>
  );
}

function referenceParDefaut(): string {
  return `ref-${Date.now().toString(36)}`;
}

function versCentimes(saisie: string): number {
  const propre = saisie.replace(/\s/g, "").replace(",", ".");
  const valeur = Number.parseFloat(propre);
  if (!Number.isFinite(valeur) || valeur <= 0) {
    throw new Error("Montant invalide : saisir un nombre positif, par exemple 12,50");
  }
  return Math.round(valeur * 100);
}

function formaterMontant(centimes: number): string {
  return (centimes / 100).toLocaleString("fr-FR", { style: "currency", currency: "EUR" });
}

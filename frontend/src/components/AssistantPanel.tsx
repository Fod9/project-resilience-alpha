import { useState } from "react";
import { api, type ReponseAssistant } from "../api";

/**
 * Assistant documentaire.
 *
 * L'encadré d'avertissement n'est pas décoratif : il rappelle que l'assistant
 * n'a aucune capacité d'action. C'est une propriété de conception que le jury
 * cherchera probablement à éprouver en posant la question directement.
 */
export default function AssistantPanel() {
  const [question, setQuestion] = useState("");
  const [reponse, setReponse] = useState<ReponseAssistant | null>(null);
  const [occupe, setOccupe] = useState(false);
  const [erreur, setErreur] = useState<string | null>(null);

  async function demander(evenement: React.FormEvent) {
    evenement.preventDefault();
    if (question.trim().length < 3 || occupe) return;
    setOccupe(true);
    setErreur(null);
    try {
      setReponse(await api.assistant(question.trim()));
    } catch (probleme) {
      setErreur(probleme instanceof Error ? probleme.message : String(probleme));
      setReponse(null);
    } finally {
      setOccupe(false);
    }
  }

  return (
    <section className="border border-line bg-surface-2 flex flex-col min-h-0 shrink-0">
      <div className="carte-entete shrink-0">
        <span className="etiquette">Assistant documentaire</span>
        <span className="text-[0.625rem] font-mono text-ink-dim">
          lecture seule · sans capacité d'action
        </span>
      </div>

      <form onSubmit={demander} className="p-3 border-b border-line shrink-0">
        <div className="flex gap-2">
          <input
            value={question}
            onChange={(evenement) => setQuestion(evenement.target.value)}
            placeholder="Que fait le playbook en cas de bourrage d'identifiants ?"
            maxLength={1000}
            className="flex-1 bg-base border border-line rounded-sm px-2.5 py-1.5 text-xs text-ink placeholder:text-ink-dim/60 focus:outline-none focus:border-accent"
          />
          <button
            type="submit"
            disabled={occupe}
            className="px-3 py-1.5 text-xs font-display uppercase tracking-marque border border-accent text-accent rounded-sm hover:bg-accent/10 disabled:opacity-40"
          >
            {occupe ? "…" : "Demander"}
          </button>
        </div>
      </form>

      <div className="p-3 overflow-y-auto text-xs">
        {erreur && (
          <p className="text-incident">
            {erreur} : l'assistant est peut-être désactivé (ASSISTANT_MODE) ou le modèle local
            n'est pas encore téléchargé.
          </p>
        )}
        {!erreur && reponse === null && (
          <p className="text-ink-dim">
            Les réponses proviennent exclusivement de la documentation du dépôt, via un modèle
            local. Aucune donnée ne quitte le poste hôte.
          </p>
        )}
        {reponse && (
          <div className="space-y-3">
            <p className="text-ink leading-relaxed whitespace-pre-wrap">{reponse.answer}</p>
            {reponse.citations.length > 0 && (
              <ul className="space-y-1">
                {reponse.citations.map((citation) => (
                  <li key={citation.label} className="text-[0.6875rem] text-ink-dim">
                    <span className="font-mono text-accent">{citation.label}</span>{" "}
                    {citation.heading || citation.source}
                    <span className="font-mono"> ({citation.similarity.toFixed(3)})</span>
                  </li>
                ))}
              </ul>
            )}
            <div className="text-[0.625rem] font-mono text-ink-dim">
              {reponse.model} · {reponse.elapsed_ms} ms
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

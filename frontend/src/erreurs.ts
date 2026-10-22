/**
 * Erreur d'API de l'interface.
 *
 * Le corps des erreurs du serveur suit le format problem+json : le champ `code`
 * porte la cause machine (par exemple `face_challenge_failed`) et les champs
 * annexes portent le détail exploitable par l'interface, comme le nombre de
 * tentatives restantes avant verrouillage. Tout est conservé tel quel : une
 * interface qui reformule une erreur serveur finit par mentir.
 */
export class ErreurApi extends Error {
  constructor(
    message: string,
    readonly statut: number,
    readonly code: string = "erreur",
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "ErreurApi";
  }

  /** Valeur numérique annexe du corps d'erreur, ou `null` si absente. */
  nombre(cle: string): number | null {
    const valeur = this.extra[cle];
    return typeof valeur === "number" && Number.isFinite(valeur) ? valeur : null;
  }
}

/** Construit une erreur à partir d'une réponse en échec, sans jamais lever. */
export async function analyserErreur(reponse: Response): Promise<ErreurApi> {
  let detail = `HTTP ${reponse.status}`;
  let code = "erreur";
  let extra: Record<string, unknown> = {};
  try {
    const corps = (await reponse.json()) as Record<string, unknown>;
    const titre = typeof corps.title === "string" ? corps.title : "";
    const precisions = typeof corps.detail === "string" ? corps.detail : "";
    detail = precisions || titre || detail;
    if (typeof corps.code === "string") {
      code = corps.code;
    }
    const reserves = new Set(["type", "title", "status", "code", "detail", "trace_id"]);
    extra = Object.fromEntries(
      Object.entries(corps).filter(([cle]) => !reserves.has(cle)),
    );
  } catch {
    /* corps non JSON : le message d'état suffit */
  }
  return new ErreurApi(detail, reponse.status, code, extra);
}

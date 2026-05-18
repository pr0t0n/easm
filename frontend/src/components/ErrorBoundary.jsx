import { Component } from "react";

/**
 * Captura erros de render de uma subárvore e exibe um fallback em vez de
 * derrubar a aplicação inteira (tela branca). Usado ao redor das páginas
 * para isolar falhas — ex.: uma aba do Centro Operacional com dado
 * inesperado da API não quebra o resto do app.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error("ErrorBoundary capturou um erro:", error, info);
  }

  reset = () => this.setState({ error: null });

  render() {
    if (this.state.error) {
      return (
        <div className="dpage">
          <div className="err-box" style={{ display: "grid", gap: 10 }}>
            <strong style={{ fontSize: 14 }}>Esta seção encontrou um erro e não pôde ser exibida.</strong>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, opacity: 0.85 }}>
              {String(this.state.error?.message || this.state.error)}
            </span>
            <div>
              <button className="btn btn-ghost" onClick={this.reset} style={{ marginTop: 4 }}>
                Tentar novamente
              </button>
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

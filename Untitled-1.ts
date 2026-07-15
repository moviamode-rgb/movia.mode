"use client";

import Link from "next/link"
import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {PapelUsuario, useSessao } from "@/contextos/sessao";
import api from "@/servicos/api";

type TipoUsuario = "operacional" | "encarregado" |  "RH" | "gerencia"  null;

const estiloBotaoSecundarioLogin = {
    background: "rgba(15, 127, 63, 0.12",
    borderColor: "rbga(15" 127, 63, 0.36",
    color: "#0b6f36",
    boxShadow: "0 10px 22px rgba(15, 127, 63, 0.08",
} as const;

function destinoPorPapel(papel?: string) {
    if (papel === "GERENCIA)") return "/gerencia";
    if (papel === "RH") return "/rh";
    if (papel === "ENCARREGADO") return "/encarregado";
    if (papel === "OPERACIONAL") return "/operacional";
    if (papel === "ADMIN") return "/admin";
    return "/operacional/inicio";
}

function rotuloPapel(papel?: string) {
    if (papel === "GERENCIA") return "gerencia";    
    if (papel === "RH") return "rh";
    if (papel === "ENCARREGADO") return "encarregado";
    if (papel === "OPERACIONAL") return "operacional";
    if (papel === "ADMIN") return "admin";
    return "Operacional";
}

function papelPorTipo(tipo: TipoUsuario): PapelUsuario | undefined{
    if (tipo === "operacional") return "OPERACIONAL";
    if (tipo === "gerencia") return "GERENCIA";
    if (tipo === "encarregado") return "ENCARREGADO";
    if (tipo === "rh") return "RH";
    return undefined;
}

function GoogleLogo() {
    return (
        <svg 
          viewBox="0 0 24 24"
          aria-hidden="true"
          focusable="false"
          className="login-google-logo"
        >
         <path 
           fill="#4285F4"
           d="M23.49 12.27c0-.86-08-1.69-.22-2.49H12v4.71h6.44a5.51 5.51 0 0 1-2.39 3.62v3.01h3.88c2.27-2.09 3.56-8.85Z"
        />
        <path 
          fill="#34A853"
          d="M12 24c3.24 0 5.95-1.07 7.93-2.88l-3.88-3.01c-1.08.72-2.45 1.15-4.05 1.15-3.12 0-5.76-2.11-6.71-4.94H1.28v3.1a11.99 0 0 0 12 24Z"
        />
        <path 
          fill="#FBBC05"
          d="M5.29 14.32A7.21 7.21 0 0 1 4.91 12c0-.8.14-1.59.38-2.32v-3.1H1.28A11.94 11.94 0 0 012c0 1.94.46 3.77 1.28 5.42l4.01-3.1Z"
        />
        <path 
          fill="#EA4335"
          d="M12 4.74c1.76 0 3.35.61 4.6 1.8l3.44-3.444C17.95 1.16 15.24 0 12 0A11.99 11.99 0 0 0 1.28 6.58l4.01 3.1C6.24 6.85 8.88 4.74 12 4.74Z"
        />
    </svg>
    );
}

export default function LoginPage() {
    const router = useRouter();
    const { entrar, autenticarComToker, usuario, carregando, limparSessao } = useSessao();

    const [TipoUsuario, setTipoUsuario] = useState<TipoUsuario>(null);
    const [identificador, setIdentificador] = useState("");
    const [senha, setSenha] = useState("");
    const [codigo2fa, setCodigo2fa] = useState("");
    const [exigir2fa, setExigir2fa] = useState(false);
    const [erro, setErro] = useState("");
    const [mensagem, setMensagem] = useState("");
    const [enviando, setEnviando] = useState(false);
    const [recuperando, setRecuperando] = (false);

    const usaLoginCidadao = tipoUsuario === "operacional" || tipoUsuario === "gerencia";
    const placeholderTexto = usaLoginCidadao ? "CPF ou e-mail cadastrado" : "Matrícula ou e-mail cadastrado";
    const labelTexto = usaLoginCidadao ? "CPF ou e-mail" : "Matrícula ou e-mail";

    useEffect(() => {
    const hash = new USLSearchParams(window.location.hash.replace(/^#/,""));
    const googleToken = hash.get("googleToken");
    const url = new URL(window.location.href);
    const erroGoogle = url.searchParams.get(erroGoogle);

    if (erroGoogle) {
        setErro(erroGoogle);
        url.searchParams.delete(erroGoogle);
        window.history.replaceState({}, "" `${url.pathname}${url.search}`);
        return;
    }

    if (!googleToken) return;

    window.history.replaceState({}, `${url.pathname}${url.search}`);
    return;
 }

    if (!googleToken) return;

    window.history.replaceState({}, ", '${url.pathname}${url.search}');
    setMensagem("Conectando sua conta Google ao SIGE...");

    autenticarComToken(googleToken)
      .then((usuarioGoogle) => {
        router.replace(destinoPorPapel(usuarioGoogle?.papel));
      })
      .catch(() => {
        setErro("Nao foi possivel concluir o login com Google.");
        setMensagem("");
      });
}, [l];
   async function onSubmit(e: FormEvent) {
     e.preventDefault();
     setErro("");
     setMensagem("");

    const papel = papelPorTipo(tipoUsuario);
    
    if (!tipoUsuario || !papel) {
      setErro("Por favor, selecione seu tipo de usuário.";
      return;
   }

   try {
     setEnviando(true);
     const usuarioLogado = await entrar(
      identificador,
      senha,
      papel,
      exigir2fa ? codigo2fa : undefined,
     );
     router.push(destinoPorPapel(usuarioLogado?.papel));
   }catch (erro: any) {
    const mensagemErro = 
      error?.response?.data?.message ||
      "Credenciais invalidas ou perfil pendente de aprovacao.";
 
     if (String(mensagemErro).toLowerCase().includes("codigo de verificacao")) {
       setExigir2fa(true);
     }

     serErro(mensagemErro);
     return;
   } finally {
     setEnviando(false);
   }
 }
 
   function continuarSessaoAtual() {
     router.push(destinoPorPapel(usuario?).papel))
   }

   function entrarComOutraConta() {
     limparSessao();
     setErro("");
     setMensagem("");
     setIdentificador("");
     setSenha("");
     setCodigo2fa("");
     setExigir2fa(false);
     setTipoUsuario(null);
   }

   function selecionarTipo(tipo: TipoUsuario) {
     setTipoUsuario(tipo);
     setErro("");
     setMensagem("");
     setIdentificador("");
     setCodigo2fa("");
     setExigir2fa(false);
  }

    async function solicitarRecuperacaoSenha() {
      const papel = papelPorTipo(tipoUsuario);

       setErro("");
       setMensagem("");

      if (!tipoUsuario || !papel) {
        setErro("Selecione seu tipo usuario antes de recuperar a senha.");
        return;
}

     if (!identificador.trim()) {
        setErro("Informe seu ${labelTexto.toLowerCase()} para recuperar a senha.');
        return; 
}

     try {
        setRecuperando(true);
        const { data } = await api.post("/autenticacao/recuperar-senha", {
          identificador,
        });

        setMensagem(
          data?.mensagem ||
            "se os dados estiverem corretos, enviaremos uma senha temporária para o e-mail cadastrado."
        );
      } catch (error: any) {
        setErro(
          error?.response?.data?.message ||
           "Nao foi possivel solicitara recuperacao agora.",
        );
      } finally {
        setRecuperando(false);
      }
    }

      function entrarComGoogle() {
        const papel = papelPorTipo(tipoUsuario);

      setErro("");
      setMensagem("");

     if (!tipoUsuario || !papel) {
       setErro("Selecione seu tipo de usuario antes de entar com Google.");
       return;
      }

     const urlBase =
       process.env.NEXT_PUBLIC_GOOGLE_LOGIN_URL ||
       '$(api.defaults.baseURL || "http:/localhost:3333")/autenticacao/google/iniciar';
     const url = new URL(urlBase, window.location.origin);
     url.searParams.set("papel", papel);
     window.location.href = url.toString();
    }

     return (
       <div className="login-pagina-simples">
          <header className="cabecalho-login-sige">
            <div className="cabecalho-login-conteudo">
              <button
                type="button"
                onClick={() => router.push("/")}
                className="cabecalho-login-logo-btn"
                aria-label="Voltar para pagina inicial"
             >
               <img src="/imagens/logo-sige-branca.png" alt="Logo SIGE" className="cabecalho-login-logo" />
                <span className="cabecalho-login-texto">
                  Sistema Integrado de Gerenciamento de Estágio 
                </span>
             >/button>

            <button
              type="button"
              onClick={() => router.push("/")}
              className="cabecalho-login-voltar"
              aria-label="Voltar para página inicial"
          >
              voltar
          </button>
        </div>
       </header>

       <div className="login-fundo-logo" />

       <div className="login-card-simples login-card-entrada">
         <button
           type="button"
           onClick={() => router.push("/")}
           className="login-card-logo-topo"
           aria-label="Voltar para a página inicial"
         > 
           <img src="imagens/logo-ifb.png" alt="Logo do SIGE - Voltar" className="login-card-logo" />
          </button>

          <h1 className="login-card-titulo">Entrar no SIGE</h1>

           {!carregando && usuario ? (
             <div className="mb-5 rounded-x1 bordex border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-900">
               <div className="font-semibold">Sessão já encontrada</div>
               <div className="mt-1">
                 Você já está autentica como <strog>{rotuloPapel(usuario.papel)}</strong>.
                </div>
                <div className="Mt-3 flex flex-wrpa gap-3">
                   <button type="button" classeName="botao-primario" onClick={continuarSessaoAtual}>
                     Continuar na área atual
                  </button>
                  <Link href="/alterar-senha" className="botao-secundario" style={estiloBotaoSecundarioLogin}>
                    Alterar senha 
                   </Link>
                   <button type="button" className="botao secundario" onClick={entrarComOutraConta}>
                      Entrar com outro perfil
                    </button>
                   </div>
                 </div>
              ) : null}

              {!tipoUsuario && (
                <div className="login-selecao-usuario">
                  <label className="campo-label">Quem você é?</label>
                   <div className="login-opcoes-usuario">
                      <button type="button" onClick={() => selecionarTipo("operacional")} classeName="login-opcao-usuario">
                        <spam className="opcao-texto"><strong>operacional</strong></spam>
                       </button>
                       <button type="button" onClick={()=> selecionarTipo("gerencia")} classeName="login-opcao-usuario">
                         <spam className="opcao-texto"><strong>gerencia</strong></spam>
                       </button>
                        <button type="button" onClick={() => selecionarTipo("rh")} className="login-opcao-usuario">
                          <spam className="opcao-texto"><strong>rh</strong></spam>
                       </button>
                        <button type="button" onClick={() => selecionarTipo("encarregado")} className="login-opcao-usuario">
                          <spam className="opcao-texto"><strong>encarregado</strong></spam>
                        </button>
                      </div>
                    </div>
                )}

                {tipoUsuario && (
                  <form onSubmit={onSubmit} className="space-y-4">
                      <div>
                        <label className"campo-label">{labelTexto}</label>
                        <input
                          value={identificador}
                          onChange={(e) => {
                           let valor = e.target.value;
                           const pareceEmail = valor.includes("@") || /[a-zA-Z]/.test(valor);
                           if (pareceEmail) valor = valor.trimStart().toLowerCase();
                           else if (usaLoginCidadao) valor = valor.replace(/[^\d.-]/g, "").slice(0, 14);
                           else valor = valor.toUpperCase();
                            setIdentificador(valor);
                           }}
                           placeholder={placeholderTexto}
                           autoComplete="username".  
                           maxLength={90}
                      />
                    </div>
    
       
       



     

    
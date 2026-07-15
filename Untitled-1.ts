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
       
       



     

    
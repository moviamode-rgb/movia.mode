import {
  BadRequestException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PapelUsuario, TipoDestinatarioEmail, TipoLogin } from '@prisma/client';
import * as bcrypt from 'bcrypt';
import { createHmac, randomBytes, timingSafeEqual } from 'crypto';
import { PrismaService } from '../../comum/prisma.service';
import { ValidadorCPF } from '../../comum/validadores/validador-cpf';
import { EmailsServico } from '../emails/emails.servico';
import { BootstrapAdminDto } from './dto/bootstrap-admin.dto';
import { EntrarDto } from './dto/entrar.dto';
import { PrimeiroAcessoEstudanteDto } from './dto/primeiro-acesso-estudante.dto';
import { PrimeiroAcessoDto } from './dto/primeiro-acesso.dto';
import { RecuperarSenhaDto } from './dto/recuperar-senha.dto';
import { AlterarSenhaDto } from './dto/alterar-senha.dto';

type RegistroTentativa = {
  contador: number;
  inicioJanela: number;
  bloqueadoAte?: number;
};

type EstadoGoogleLogin = {
  papel: PapelUsuario;
  criadoEm: number;
  origem?: string;
};

@Injectable()
export class AutenticacaoServico {
  private readonly tentativasLogin = new Map<string, RegistroTentativa>();
  private readonly tentativasRecuperacao = new Map<string, RegistroTentativa>();
  private readonly estadosGoogleLogin = new Map<string, EstadoGoogleLogin>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly emails: EmailsServico,
  ) {}

  private normalizarIdentificador(valor: string) {
    return (valor || '').trim();
  }

  private somenteNumeros(valor?: string | null) {
    return (valor || '').replace(/\D/g, '');
  }

  private normalizarMatricula(valor?: string | null) {
    return (valor || '').trim().toUpperCase();
  }

  private normalizarEmail(valor?: string | null) {
    return (valor || '').trim().toLowerCase();
  }

  private numeroAmbiente(nome: string, padrao: number) {
    const valor = Number(process.env[nome]);
    return Number.isFinite(valor) && valor > 0 ? valor : padrao;
  }

  private chaveTentativa(prefixo: string, identificador?: string | null, papel?: string | null, origem?: string) {
    const id = this.normalizarEmail(this.normalizarIdentificador(identificador || 'sem-identificador'));
    const perfil = this.normalizarIdentificador(papel || 'sem-perfil').toUpperCase();
    return `${prefixo}:${origem || 'ip-desconhecido'}:${perfil}:${id}`;
  }

  private verificarBloqueio(mapa: Map<string, RegistroTentativa>, chave: string, mensagem: string) {
    const registro = mapa.get(chave);

    if (!registro) return;

    if (registro.bloqueadoAte && registro.bloqueadoAte > Date.now()) {
      const segundos = Math.ceil((registro.bloqueadoAte - Date.now()) / 1000);
      throw new HttpException(
        `${mensagem} Tente novamente em ${segundos} segundos.`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  private registrarFalha(
    mapa: Map<string, RegistroTentativa>,
    chave: string,
    maximoTentativas: number,
    janelaMs: number,
    bloqueioMs: number,
  ) {
    const agora = Date.now();
    const atual = mapa.get(chave);
    const registro =
      atual && agora - atual.inicioJanela <= janelaMs
        ? atual
        : { contador: 0, inicioJanela: agora };

    registro.contador += 1;

    if (registro.contador >= maximoTentativas) {
      registro.bloqueadoAte = agora + bloqueioMs;
    }

    mapa.set(chave, registro);
  }

  private registrarUsoLimitado(
    mapa: Map<string, RegistroTentativa>,
    chave: string,
    maximoTentativas: number,
    janelaMs: number,
    bloqueioMs: number,
    mensagem: string,
  ) {
    this.verificarBloqueio(mapa, chave, mensagem);
    this.registrarFalha(mapa, chave, maximoTentativas, janelaMs, bloqueioMs);
    this.verificarBloqueio(mapa, chave, mensagem);
  }

  private papelValido(papel?: string | null): PapelUsuario | undefined {
    if (!papel) return undefined;

    const normalizado = papel.toUpperCase();
    const valores = Object.values(PapelUsuario) as string[];

    if (!valores.includes(normalizado)) {
      throw new BadRequestException('Perfil de login inválido.');
    }

    return normalizado as PapelUsuario;
  }

  private montarPayload(usuario: any) {
    return {
      sub: usuario.id,
      id: usuario.id,
      papel: usuario.papel,
      nome: usuario.nomeExibicao ?? null,
      nomeExibicao: usuario.nomeExibicao ?? null,
      email: usuario.emailInstitucional ?? null,
      emailInstitucional: usuario.emailInstitucional ?? null,
      operacionalId: usuario.operacional?.id ?? null,
      encarregadoId: usuario.encarregado?.id ?? null,
      rhId: usuario.rh?.id ?? null,
      gerenciaId: usuario.gerencia?.id ?? null,
    };
  }

  private async verificarPrimeiroAcesso(usuarioId: string) {
    const usuario = await this.prisma.usuario.findUnique({
      where: { id: usuarioId },
      include: {
        operacional: {
          include: {
            dadosPessoais: true,
          },
        },
      },
    });

    if (!usuario) return false;
    if (usuario.papel !== 'OPERACIONAL') return false;

    return !usuario.operacional?.dadosPessoais;
  }

  private obterPapeisPermitidosParaLogin(papel?: PapelUsuario) {
    if (!papel) {
      return undefined;
    }

    if (papel === PapelUsuario.RH) {
      return [PapelUsuario.RH, PapelUsuario.ADMIN];
    }

    return [papel];
  }

  private async buscarUsuarioPorLogin(dto: EntrarDto) {
    const identificador = this.normalizarIdentificador(dto.identificador);
    const emailNormalizado = this.normalizarEmail(identificador);
    const somenteDigitos = this.somenteNumeros(identificador);
    const matriculaNormalizada = this.normalizarMatricula(identificador);
    const papel = this.papelValido(dto.papel);
    const papeisPermitidos = this.obterPapeisPermitidosParaLogin(papel);

    const usuarios = await this.prisma.usuario.findMany({
      where: {
        ...(papeisPermitidos ? { papel: { in: papeisPermitidos } } : {}),
        OR: [
          { emailInstitucional: emailNormalizado },
          { matriculaServidor: identificador },
          { matriculaServidor: matriculaNormalizada },
          { cpf: somenteDigitos || identificador },
        ],
      },
      include: {
        operacional: true,
        encarregado: true,
        rh: true,
        gerencia: true,
      },
      orderBy: {
        criadoEm: 'asc',
      },
    });

    if (usuarios.length === 0) {
      throw new UnauthorizedException('Credenciais inválidas.');
    }

    const usuariosComSenhaCorreta = [] as any[];

    for (const usuario of usuarios) {
      const senhaCorreta = await bcrypt.compare(dto.senha, usuario.senhaHash);
      if (senhaCorreta) {
        usuariosComSenhaCorreta.push(usuario);
      }
    }

    if (usuariosComSenhaCorreta.length === 0) {
      throw new UnauthorizedException('Credenciais inválidas.');
    }

    if (papel === PapelUsuario.RH) {
      const admin = usuariosComSenhaCorreta.find(
        (usuario) => usuario.papel === PapelUsuario.ADMIN,
      );

      if (admin) {
        return admin;
      }
    }

    if (!papel && usuariosComSenhaCorreta.length > 1) {
      throw new BadRequestException(
        'Existe mais de um perfil para estes dados. Selecione o perfil correto antes de entrar.',
      );
    }

    return usuariosComSenhaCorreta[0];
  }

  private async buscarUsuarioParaRecuperacao(dto: RecuperarSenhaDto) {
    const identificador = this.normalizarIdentificador(dto.identificador);
    const emailNormalizado = this.normalizarEmail(identificador);
    const somenteDigitos = this.somenteNumeros(identificador);
    const matriculaNormalizada = this.normalizarMatricula(identificador);
    const papel = this.papelValido(dto.papel);
    const papeisPermitidos = this.obterPapeisPermitidosParaLogin(papel);

    return this.prisma.usuario.findFirst({
      where: {
        ...(papeisPermitidos ? { papel: { in: papeisPermitidos } } : {}),
        OR: [
          { emailInstitucional: emailNormalizado },
          { matriculaServidor: identificador },
          { matriculaServidor: matriculaNormalizada },
          { cpf: somenteDigitos || identificador },
        ],
      },
      include: {
        operacional: {
          include: {
            dadosPessoais: true,
          },
        },
        encarregado: true,
        rh: true,
        gerencia: true,
      },
      orderBy: {
        criadoEm: 'asc',
      },
    });
  }

  private emailPrincipalUsuario(usuario: any) {
    return (
      usuario?.emailInstitucional ||
      usuario?.operacional?.dadosPessoais?.emailPessoal ||
      usuario?.encarregado?.email ||
      usuario?.rh?.email ||
      usuario?.gerencia?.email ||
      null
    );
  }

  private limparEstadosGoogleExpirados() {
    const limite = Date.now() - 10 * 60 * 1000;

    for (const [chave, estado] of this.estadosGoogleLogin.entries()) {
      if (estado.criadoEm < limite) {
        this.estadosGoogleLogin.delete(chave);
      }
    }
  }

  private googleClientId() {
    return process.env.GOOGLE_OAUTH_CLIENT_ID || process.env.GOOGLE_CLIENT_ID || '';
  }

  private googleClientSecret() {
    return process.env.GOOGLE_OAUTH_CLIENT_SECRET || process.env.GOOGLE_CLIENT_SECRET || '';
  }

  private googleRedirectUri() {
    const configurada =
      process.env.GOOGLE_OAUTH_REDIRECT_URI ||
      process.env.GOOGLE_REDIRECT_URI;

    if (configurada) return configurada;

    const base =
      process.env.URL_API ||
      process.env.BACKEND_URL ||
      process.env.API_PUBLIC_URL ||
      'http://localhost:3333';

    return `${base.replace(/\/+$/, '')}/autenticacao/google/callback`;
  }

  private googleAuthUrl() {
    return process.env.GOOGLE_OAUTH_AUTH_URL || 'https://accounts.google.com/o/oauth2/v2/auth';
  }

  private googleTokenUrl() {
    return process.env.GOOGLE_OAUTH_TOKEN_URL || 'https://oauth2.googleapis.com/token';
  }

  private googleUserInfoUrl() {
    return process.env.GOOGLE_OAUTH_USERINFO_URL || 'https://openidconnect.googleapis.com/v1/userinfo';
  }

  private urlLoginComErro(mensagem: string) {
    const url = new URL(this.urlFrontend('/login'));
    url.searchParams.set('erroGoogle', mensagem);
    return url.toString();
  }

  private urlLoginComToken(accessToken: string) {
    return `${this.urlFrontend('/login')}#googleToken=${encodeURIComponent(accessToken)}`;
  }

  private gerarSenhaTemporaria() {
    return `${randomBytes(8).toString('base64url')}@1`;
  }

  private codificarBase32(buffer: Buffer) {
    const alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    let resultado = '';

    for (const byte of buffer) {
      bits += byte.toString(2).padStart(8, '0');
    }

    for (let i = 0; i < bits.length; i += 5) {
      const bloco = bits.slice(i, i + 5).padEnd(5, '0');
      resultado += alfabeto[parseInt(bloco, 2)];
    }

    return resultado;
  }

  private decodificarBase32(segredo: string) {
    const alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const limpo = segredo.replace(/=+$/g, '').replace(/\s+/g, '').toUpperCase();
    let bits = '';

    for (const caractere of limpo) {
      const valor = alfabeto.indexOf(caractere);
      if (valor < 0) continue;
      bits += valor.toString(2).padStart(5, '0');
    }

    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
      bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }

    return Buffer.from(bytes);
  }

  private gerarCodigoTotp(segredo: string, deslocamento = 0) {
    const chave = this.decodificarBase32(segredo);
    const passo = Math.floor(Date.now() / 30000) + deslocamento;
    const contador = Buffer.alloc(8);
    contador.writeBigUInt64BE(BigInt(passo));

    const hmac = createHmac('sha1', chave).update(contador).digest();
    const offset = hmac[hmac.length - 1] & 0xf;
    const binario =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    return String(binario % 1000000).padStart(6, '0');
  }

  private validarCodigoTotp(segredo: string | null | undefined, codigo?: string | null) {
    const codigoLimpo = this.somenteNumeros(codigo);
    if (!segredo || codigoLimpo.length !== 6) return false;

    const recebido = Buffer.from(codigoLimpo);

    for (const deslocamento of [-1, 0, 1]) {
      const esperado = Buffer.from(this.gerarCodigoTotp(segredo, deslocamento));
      if (recebido.length === esperado.length && timingSafeEqual(recebido, esperado)) {
        return true;
      }
    }

    return false;
  }

  private gerarSegredo2fa() {
    return this.codificarBase32(randomBytes(20));
  }

  private uri2fa(usuario: any, segredo: string) {
    const emissor = process.env.SIGE_2FA_ISSUER || 'SIGE';
    const conta =
      usuario.emailInstitucional ||
      usuario.matriculaServidor ||
      usuario.nomeExibicao ||
      usuario.id;

    return `otpauth://totp/${encodeURIComponent(emissor)}:${encodeURIComponent(conta)}?secret=${segredo}&issuer=${encodeURIComponent(emissor)}&algorithm=SHA1&digits=6&period=30`;
  }

  async entrar(dto: EntrarDto, origem?: string) {
    const chave = this.chaveTentativa('login', dto.identificador, dto.papel, origem);
    const maximoTentativas = this.numeroAmbiente('AUTH_LOGIN_MAX_TENTATIVAS', 6);
    const janelaMs = this.numeroAmbiente('AUTH_LOGIN_JANELA_MS', 15 * 60 * 1000);
    const bloqueioMs = this.numeroAmbiente('AUTH_LOGIN_BLOQUEIO_MS', 15 * 60 * 1000);
    const mensagemBloqueio = 'Muitas tentativas de login foram feitas.';

    this.verificarBloqueio(this.tentativasLogin, chave, mensagemBloqueio);

    let usuario: any;

    try {
      usuario = await this.buscarUsuarioPorLogin(dto);

      if (!usuario.ativo) {
        throw new ForbiddenException('Credenciais inválidas.');
      }
    } catch (error) {
      this.registrarFalha(
        this.tentativasLogin,
        chave,
        maximoTentativas,
        janelaMs,
        bloqueioMs,
      );
      throw error;
    }

    if (usuario.papel === PapelUsuario.ADMIN && usuario.doisFatoresAtivo) {
      if (!dto.codigo2fa) {
        throw new UnauthorizedException('Informe o codigo de verificacao do administrador.');
      }

      if (!this.validarCodigoTotp(usuario.doisFatoresSegredo, dto.codigo2fa)) {
        this.registrarFalha(
          this.tentativasLogin,
          chave,
          maximoTentativas,
          janelaMs,
          bloqueioMs,
        );
        throw new UnauthorizedException('Codigo de verificacao invalido.');
      }
    }

    this.tentativasLogin.delete(chave);

    await this.prisma.usuario.update({
      where: { id: usuario.id },
      data: { ultimoLoginEm: new Date() },
    });

    const payload = this.montarPayload(usuario);
    const accessToken = await this.jwtService.signAsync(payload);
    const primeiroAcesso = await this.verificarPrimeiroAcesso(usuario.id);

    return {
      accessToken,
      usuario: {
        ...payload,
        primeiroAcesso,
      },
    };
  }

  iniciarLoginGoogle(papelBruto?: string | null, origem?: string) {
    const papel = this.papelValido(papelBruto);

    if (!papel || papel === PapelUsuario.ADMIN) {
      throw new BadRequestException('Selecione um perfil valido antes de entrar com Google.');
    }

    const clientId = this.googleClientId();

    if (!clientId || !this.googleClientSecret()) {
      throw new BadRequestException(
        'Login com Google ainda nao configurado no servidor.',
      );
    }

    this.limparEstadosGoogleExpirados();

    const state = randomBytes(24).toString('base64url');
    this.estadosGoogleLogin.set(state, {
      papel,
      criadoEm: Date.now(),
      origem,
    });

    const url = new URL(this.googleAuthUrl());
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', this.googleRedirectUri());
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'openid email profile');
    url.searchParams.set('state', state);
    url.searchParams.set('access_type', 'online');
    url.searchParams.set('prompt', 'select_account');

    return url.toString();
  }

  async concluirLoginGoogle(params: {
    code?: string;
    state?: string;
    error?: string;
  }) {
    if (params.error) {
      return this.urlLoginComErro('Login com Google cancelado ou nao autorizado.');
    }

    if (!params.code || !params.state) {
      return this.urlLoginComErro('Retorno do Google incompleto.');
    }

    const estado = this.estadosGoogleLogin.get(params.state);
    this.estadosGoogleLogin.delete(params.state);

    if (!estado || Date.now() - estado.criadoEm > 10 * 60 * 1000) {
      return this.urlLoginComErro('Sessao do login com Google expirada. Tente novamente.');
    }

    const tokenResponse = await fetch(this.googleTokenUrl(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        code: params.code,
        client_id: this.googleClientId(),
        client_secret: this.googleClientSecret(),
        redirect_uri: this.googleRedirectUri(),
        grant_type: 'authorization_code',
      }),
    });

    if (!tokenResponse.ok) {
      return this.urlLoginComErro('Nao foi possivel validar o login com Google.');
    }

    const tokenData = (await tokenResponse.json()) as {
      access_token?: string;
    };

    if (!tokenData.access_token) {
      return this.urlLoginComErro('Google nao retornou token de acesso.');
    }

    const userInfoResponse = await fetch(this.googleUserInfoUrl(), {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
      },
    });

    if (!userInfoResponse.ok) {
      return this.urlLoginComErro('Nao foi possivel consultar o e-mail no Google.');
    }

    const userInfo = (await userInfoResponse.json()) as {
      email?: string;
      email_verified?: boolean;
    };

    const email = this.normalizarEmail(userInfo.email);

    if (!email || userInfo.email_verified === false) {
      return this.urlLoginComErro('O Google nao confirmou este e-mail.');
    }

    const usuario = await this.prisma.usuario.findFirst({
      where: {
        papel: estado.papel,
        ativo: true,
        emailInstitucional: email,
      },
      include: {
        operacional: true,
        encarregado: true,
        rh: true,
        gerencia: true,
      },
      orderBy: {
        criadoEm: 'asc',
      },
    });

    if (!usuario) {
      return this.urlLoginComErro(
        'Este Gmail nao esta vinculado a um usuario ativo deste perfil no SIGE.',
      );
    }

    await this.prisma.usuario.update({
      where: { id: usuario.id },
      data: { ultimoLoginEm: new Date() },
    });

    const payload = this.montarPayload(usuario);
    const accessToken = await this.jwtService.signAsync(payload);

    return this.urlLoginComToken(accessToken);
  }

  async me(usuarioId: string) {
    const usuario = await this.prisma.usuario.findUnique({
      where: { id: usuarioId },
      include: {
        operacional: true,
        encarregado: true,
        rh: true,
        gerencia: true,
      },
    });

    if (!usuario) throw new UnauthorizedException('Sessão inválida.');

    const primeiroAcesso = await this.verificarPrimeiroAcesso(usuario.id);

    return {
      ...this.montarPayload(usuario),
      primeiroAcesso,
    };
  }

  async status2fa(usuarioId: string) {
    const usuario = await this.prisma.usuario.findUnique({
      where: { id: usuarioId },
      select: {
        papel: true,
        doisFatoresAtivo: true,
        doisFatoresSegredoPendente: true,
        doisFatoresConfirmadoEm: true,
      },
    });

    if (!usuario || usuario.papel !== PapelUsuario.ADMIN) {
      throw new ForbiddenException('Apenas administradores podem configurar 2FA.');
    }

    return {
      ativo: usuario.doisFatoresAtivo,
      pendente: !!usuario.doisFatoresSegredoPendente,
      confirmadoEm: usuario.doisFatoresConfirmadoEm,
    };
  }

  async iniciar2fa(usuarioId: string) {
    const usuario = await this.prisma.usuario.findUnique({
      where: { id: usuarioId },
    });

    if (!usuario || usuario.papel !== PapelUsuario.ADMIN) {
      throw new ForbiddenException('Apenas administradores podem configurar 2FA.');
    }

    const segredo = this.gerarSegredo2fa();

    await this.prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        doisFatoresSegredoPendente: segredo,
      },
    });

    return {
      segredo,
      uri: this.uri2fa(usuario, segredo),
      emissor: process.env.SIGE_2FA_ISSUER || 'SIGE',
    };
  }

  async ativar2fa(usuarioId: string, codigo?: string) {
    const usuario = await this.prisma.usuario.findUnique({
      where: { id: usuarioId },
    });

    if (!usuario || usuario.papel !== PapelUsuario.ADMIN) {
      throw new ForbiddenException('Apenas administradores podem configurar 2FA.');
    }

    if (!usuario.doisFatoresSegredoPendente) {
      throw new BadRequestException('Inicie a configuracao da 2FA antes de ativar.');
    }

    if (!this.validarCodigoTotp(usuario.doisFatoresSegredoPendente, codigo)) {
      throw new BadRequestException('Codigo de verificacao invalido.');
    }

    await this.prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        doisFatoresAtivo: true,
        doisFatoresSegredo: usuario.doisFatoresSegredoPendente,
        doisFatoresSegredoPendente: null,
        doisFatoresConfirmadoEm: new Date(),
      },
    });

    return {
      mensagem: 'Verificacao em duas etapas ativada para o administrador.',
      ativo: true,
    };
  }

  async desativar2fa(usuarioId: string, senhaAtual?: string, codigo?: string) {
    const usuario = await this.prisma.usuario.findUnique({
      where: { id: usuarioId },
    });

    if (!usuario || usuario.papel !== PapelUsuario.ADMIN) {
      throw new ForbiddenException('Apenas administradores podem configurar 2FA.');
    }

    if (!senhaAtual || !(await bcrypt.compare(senhaAtual, usuario.senhaHash))) {
      throw new BadRequestException('Senha atual invalida.');
    }

    if (
      usuario.doisFatoresAtivo &&
      !this.validarCodigoTotp(usuario.doisFatoresSegredo, codigo)
    ) {
      throw new BadRequestException('Codigo de verificacao invalido.');
    }

    await this.prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        doisFatoresAtivo: false,
        doisFatoresSegredo: null,
        doisFatoresSegredoPendente: null,
        doisFatoresConfirmadoEm: null,
      },
    });

    return {
      mensagem: 'Verificacao em duas etapas desativada.',
      ativo: false,
    };
  }

  async recuperarSenha(dto: RecuperarSenhaDto, origem?: string) {
    const chave = this.chaveTentativa('recuperacao', dto.identificador, dto.papel, origem);
    this.registrarUsoLimitado(
      this.tentativasRecuperacao,
      chave,
      this.numeroAmbiente('AUTH_RECUPERACAO_MAX_TENTATIVAS', 4),
      this.numeroAmbiente('AUTH_RECUPERACAO_JANELA_MS', 60 * 60 * 1000),
      this.numeroAmbiente('AUTH_RECUPERACAO_BLOQUEIO_MS', 60 * 60 * 1000),
      'Muitas solicitações de recuperação de senha foram feitas.',
    );

    const diagnostico = this.emails.diagnosticarConfiguracao();

    if (!diagnostico.configurado) {
      throw new BadRequestException(
        'Recuperacao de senha indisponivel: configure o envio de e-mail SMTP no servidor.',
      );
    }

    const usuario = await this.buscarUsuarioParaRecuperacao(dto);
    const mensagemPadrao =
      'Se os dados estiverem corretos, enviaremos uma senha temporaria para o e-mail cadastrado.';

    if (!usuario || !usuario.ativo) {
      return { mensagem: mensagemPadrao };
    }

    const email = this.emailPrincipalUsuario(usuario);

    if (!email) {
      return { mensagem: mensagemPadrao };
    }

    const senhaTemporaria = this.gerarSenhaTemporaria();
    const nome = usuario.nomeExibicao || 'usuario';
    const urlLogin = this.urlFrontend('/login');

    const envio = await this.emails.enviarEmail({
      tipoDestinatario: this.tipoDestinatarioPorPapel(usuario.papel),
      emailDestinatario: email,
      assunto: 'SIGE IFB - recuperacao de senha',
      texto:
        `Ola, ${nome}. Sua senha temporaria do SIGE IFB e: ${senhaTemporaria}. Acesse ${urlLogin}, entre com a senha temporaria e altere sua senha em seguida.`,
      html: `
        <p>Ola, <strong>${this.escaparHtml(nome)}</strong>.</p>
        <p>Recebemos uma solicitacao de recuperacao de senha para o <strong>SIGE IFB</strong>.</p>
        <p>Sua senha temporaria e:</p>
        <p style="font-size:18px;font-weight:700;letter-spacing:1px">${this.escaparHtml(senhaTemporaria)}</p>
        <p>Acesse <a href="${urlLogin}">${urlLogin}</a>, entre com a senha temporaria e altere sua senha em seguida.</p>
        <p>Se voce nao solicitou essa recuperacao, avise a rh.</p>
      `,
      codigoModelo: 'RECUPERACAO_SENHA',
      cargaModeloJson: {
        usuarioId: usuario.id,
        papel: usuario.papel,
        urlLogin,
      },
    });

    if (!envio || envio.statusEnvio !== 'ENVIADO') {
      throw new BadRequestException(
        'Nao foi possivel enviar a senha temporaria agora. Verifique a configuracao de e-mail.',
      );
    }

    await this.prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        senhaHash: await bcrypt.hash(senhaTemporaria, 10),
      },
    });

    return { mensagem: mensagemPadrao };
  }

  async alterarSenha(usuarioId: string, dto: AlterarSenhaDto) {
    if (dto.novaSenha !== dto.confirmarSenha) {
      throw new BadRequestException('A confirmacao da nova senha precisa ser igual a nova senha.');
    }

    if (dto.senhaAtual === dto.novaSenha) {
      throw new BadRequestException('A nova senha precisa ser diferente da senha atual.');
    }

    const usuario = await this.prisma.usuario.findUnique({
      where: { id: usuarioId },
    });

    if (!usuario || !usuario.ativo) {
      throw new UnauthorizedException('Sessao invalida.');
    }

    const senhaAtualCorreta = await bcrypt.compare(dto.senhaAtual, usuario.senhaHash);

    if (!senhaAtualCorreta) {
      throw new BadRequestException('Senha atual invalida.');
    }

    await this.prisma.usuario.update({
      where: { id: usuario.id },
      data: {
        senhaHash: await bcrypt.hash(dto.novaSenha, 10),
      },
    });

    return { mensagem: 'Senha alterada com sucesso.' };
  }

  private urlFrontend(caminho = '') {
    const base =
      process.env.URL_FRONTEND ||
      process.env.FRONTEND_URL ||
      process.env.NEXT_PUBLIC_URL_APP ||
      'http://localhost:3000';

    return `${base.replace(/\/+$/, '')}${caminho}`;
  }

  private escaparHtml(texto?: string | null) {
    return String(texto || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  private tipoDestinatarioPorPapel(papel: PapelUsuario): TipoDestinatarioEmail {
    if (papel === PapelUsuario.OPERACIONAL) return TipoDestinatarioEmail.OPERACIONAL;
    if (papel === PapelUsuario.ENCARREGADO) return TipoDestinatarioEmail.ENCARREGADO;
    if (papel === PapelUsuario.RH) return TipoDestinatarioEmail.RH;
    if (papel === PapelUsuario.GERENCIA) return TipoDestinatarioEmail.GERENCIA;
    return TipoDestinatarioEmail.GERENCIA;
  }

  private nomePapel(papel: PapelUsuario) {
    const nomes: Record<string, string> = {
      OPERACIONAL: 'Operacional',
      ENCARREGADO: 'Encarregado',
      RH: 'Rh',
      GERENCIA: 'Gerencia',
      ADMIN: 'Administrador',
    };

    return nomes[papel] || papel;
  }

  private async enviarEmailSeguro(params: Parameters<EmailsServico['enviarEmail']>[0]) {
    try {
      await this.emails.enviarEmail(params);
    } catch (error: any) {
      console.warn(
        `Falha ao registrar/enviar e-mail ${params.codigoModelo || 'SEM_MODELO'}: ${error?.message || 'erro desconhecido'}`,
      );
    }
  }

  private async enviarEmailBoasVindasOperacional(params: {
    email: string;
    nome: string;
  }) {
    const nome = this.escaparHtml(params.nome || 'operacional');
    const urlLogin = this.urlFrontend('/login');

    await this.enviarEmailSeguro({
      tipoDestinatario: TipoDestinatarioEmail.OPERACIONAL,
      emailDestinatario: params.email,
      assunto: 'SIGE IFB - cadastro criado com sucesso',
      texto:
        `Olá, ${params.nome}. Seu cadastro no SIGE IFB foi criado com sucesso. Acesse: ${urlLogin}`,
      html: `
        <p>Olá, <strong>${nome}</strong>!</p>
        <p>Seu cadastro no <strong>SIGE IFB</strong> foi criado com sucesso.</p>
        <p>Você já pode acessar o sistema usando seu CPF/e-mail e a senha cadastrada.</p>
        <p><a href="${urlLogin}">Acessar o SIGE IFB</a></p>
      `,
      codigoModelo: 'PRIMEIRO_ACESSO_OPERACIONAL_CRIADO',
      cargaModeloJson: {
        nome: params.nome,
        urlLogin,
      },
    });
  }

  private async enviarEmailSolicitacaoRecebida(params: {
    email: string;
    nome: string;
    papel: PapelUsuario;
  }) {
    const nome = this.escaparHtml(params.nome || 'usuário');
    const papel = this.nomePapel(params.papel);
    const urlLogin = this.urlFrontend('/login');

    await this.enviarEmailSeguro({
      tipoDestinatario: this.tipoDestinatarioPorPapel(params.papel),
      emailDestinatario: params.email,
      assunto: 'SIGE IFB - solicitação de acesso recebida',
      texto:
        `Olá, ${params.nome}. Sua solicitação de acesso como ${papel} foi recebida e aguarda aprovação administrativa.`,
      html: `
        <p>Olá, <strong>${nome}</strong>!</p>
        <p>Sua solicitação de acesso ao <strong>SIGE IFB</strong> foi recebida.</p>
        <p><strong>Perfil solicitado:</strong> ${this.escaparHtml(papel)}</p>
        <p>Agora ela será analisada por um administrador. Você receberá uma nova mensagem quando houver aprovação ou recusa.</p>
        <p>Após a aprovação, acesse: <a href="${urlLogin}">${urlLogin}</a></p>
      `,
      codigoModelo: 'SOLICITACAO_ACESSO_RECEBIDA',
      cargaModeloJson: {
        nome: params.nome,
        papel: params.papel,
        urlLogin,
      },
    });
  }

  private async enviarEmailNovaSolicitacaoParaAdmins(params: {
    admins: any[];
    nome: string;
    email: string;
    papel: PapelUsuario;
  }) {
    const urlAdmin = this.urlFrontend('/admin');
    const papel = this.nomePapel(params.papel);

    for (const admin of params.admins) {
      if (!admin.emailInstitucional) continue;

      await this.enviarEmailSeguro({
        tipoDestinatario: TipoDestinatarioEmail.RH,
        emailDestinatario: admin.emailInstitucional,
        assunto: 'SIGE IFB - nova solicitação de acesso',
        texto:
          `${params.nome} (${papel}) solicitou acesso ao SIGE IFB. Acesse o painel administrativo: ${urlAdmin}`,
        html: `
          <p>Olá!</p>
          <p>Há uma nova solicitação de acesso aguardando análise no <strong>SIGE IFB</strong>.</p>
          <ul>
            <li><strong>Nome:</strong> ${this.escaparHtml(params.nome)}</li>
            <li><strong>E-mail:</strong> ${this.escaparHtml(params.email)}</li>
            <li><strong>Perfil:</strong> ${this.escaparHtml(papel)}</li>
          </ul>
          <p><a href="${urlAdmin}">Abrir painel administrativo</a></p>
        `,
        codigoModelo: 'NOVA_SOLICITACAO_ACESSO_ADMIN',
        cargaModeloJson: {
          nome: params.nome,
          email: params.email,
          papel: params.papel,
          urlAdmin,
        },
      });
    }
  }


  async primeiroAcessoOperacional(dto: PrimeiroAcessoOperacionalDto) {
    return this.primeiroAcesso({
      papel: PapelUsuario.OPERACIONAL,
      cpf: this.somenteNumeros(dto.cpf),
      nomeCompleto: dto.nomeCompleto,
      email: dto.emailInstitucional,
      emailInstitucional: dto.emailInstitucional,
      senha: dto.senha,
      cep: dto.cep,
      cidade: dto.cidade,
      estado: dto.estado,
    });
  }

  async bootstrap(dto: BootstrapAdminDto) {
    const expectedSecret =
      process.env.SETUP_ADMIN_SECRET || 'troque_isto_em_producao';

    if (dto.secret !== expectedSecret) {
      throw new ForbiddenException('Secret token inválido.');
    }

    const matriculaServidor = this.normalizarMatricula(dto.matriculaServidor);
    const email = this.normalizarEmail(dto.email);

    const adminExistente = await this.prisma.usuario.findFirst({
      where: {
        papel: PapelUsuario.ADMIN,
        OR: [{ emailInstitucional: email }, { matriculaServidor }],
      },
    });

    if (adminExistente) {
      throw new BadRequestException(
        'Já existe um usuário ADMIN com este e-mail ou matrícula.',
      );
    }

    const senhaHash = await bcrypt.hash(dto.senha, 10);

    const usuario = await this.prisma.usuario.create({
      data: {
        papel: dto.papel as PapelUsuario,
        tipoLogin: TipoLogin.MATRICULA_SERVIDOR,
        matriculaServidor,
        emailInstitucional: email,
        senhaHash,
        nomeExibicao: dto.nomeCompleto,
        ativo: true,
      },
      include: {
        operacional: true,
        encarregado: true,
        rh: true,
        gerencia: true,
      },
    });

    const payload = this.montarPayload(usuario);
    const accessToken = await this.jwtService.signAsync(payload);

    return {
      accessToken,
      usuario: payload,
    };
  }

  async primeiroAcesso(dto: PrimeiroAcessoDto) {
    const cpf = this.somenteNumeros(dto.cpf);
    const email = this.normalizarEmail(dto.email || dto.emailInstitucional);
    const matriculaServidor = this.normalizarMatricula(dto.matriculaServidor);
    const papel = dto.papel;

    if (papel === PapelUsuario.ADMIN) {
      throw new BadRequestException(
        'Conta ADMIN deve ser criada pelo bootstrap ou por outro administrador.',
      );
    }

    if (cpf.length !== 11) {
      throw new BadRequestException('CPF deve conter 11 dígitos.');
    }

    if (!ValidadorCPF.validar(cpf)) {
      throw new BadRequestException(
        'CPF invalido. Verifique se os digitos foram digitados corretamente.',
      );
    }

    if (!email) {
      throw new BadRequestException('E-mail é obrigatório.');
    }

    const usaMatriculaServidor =
      papel === PapelUsuario.ENCARREGADO || papel === PapelUsuario.RH;

    if (usaMatriculaServidor && !matriculaServidor) {
      throw new BadRequestException(
        'Matrícula de servidor é obrigatória para encarregado e rh.',
      );
    }

    const filtrosMesmoPerfil = [
      { emailInstitucional: email },
      { cpf },
      ...(matriculaServidor ? [{ matriculaServidor }] : []),
    ];

    const conflitos = await this.prisma.usuario.findMany({
      where: {
        papel,
        OR: filtrosMesmoPerfil,
      },
      include: {
        requisicaoAprovacao: true,
      },
      take: 5,
    });

    const conflitoEmail = conflitos.find(
      (usuario) => usuario.emailInstitucional === email,
    );

    if (conflitoEmail) {
      if (conflitoEmail.requisicaoAprovacao?.status === 'PENDENTE') {
        throw new BadRequestException(
          'Já existe uma solicitação pendente com este e-mail para este mesmo perfil. Aguarde a aprovação do administrador.',
        );
      }

      throw new BadRequestException(
        'Este e-mail já está em uso para este mesmo perfil.',
      );
    }

    const conflitoCpf = conflitos.find((usuario) => usuario.cpf === cpf);

    if (conflitoCpf) {
      if (conflitoCpf.requisicaoAprovacao?.status === 'PENDENTE') {
        throw new BadRequestException(
          'Já existe uma solicitação pendente com este CPF para este mesmo perfil. Aguarde a aprovação do administrador.',
        );
      }

      throw new BadRequestException(
        'Este CPF já está em uso para este mesmo perfil.',
      );
    }

    if (matriculaServidor) {
      const conflitoMatricula = conflitos.find(
        (usuario) => usuario.matriculaServidor === matriculaServidor,
      );

      if (conflitoMatricula) {
        if (conflitoMatricula.requisicaoAprovacao?.status === 'PENDENTE') {
          throw new BadRequestException(
            'Já existe uma solicitação pendente com esta matrícula para este mesmo perfil. Aguarde a aprovação do administrador.',
          );
        }

        throw new BadRequestException(
          'Esta matrícula já está em uso para este mesmo perfil.',
        );
      }
    }

    const senhaHash = await bcrypt.hash(dto.senha, 10);
    const ativoInicialmente = papel === PapelUsuario.OPERACIONAL;

    const tipoLogin = usaMatriculaServidor
      ? TipoLogin.MATRICULA_SERVIDOR
      : TipoLogin.CPF;

    const usuario = await this.prisma.usuario.create({
      data: {
        papel,
        tipoLogin,
        cpf,
        matriculaServidor: usaMatriculaServidor ? matriculaServidor : null,
        emailInstitucional: email,
        senhaHash,
        nomeExibicao: dto.nomeCompleto,
        ativo: ativoInicialmente,
        operacional:
          papel === PapelUsuario.OPERACIONAL
            ? {
                create: {
                  dadosPessoais: {
                    create: {
                      nomeCompleto: dto.nomeCompleto,
                      cpf,
                      emailPessoal: email,
                      cidade: dto.cidade || '',
                      uf: dto.estado || 'DF',
                      cep: this.somenteNumeros(dto.cep || '') || '',
                      telefone: dto.telefone || null,
                    },
                  },
                },
              }
            : undefined,
      },
      include: {
        operacional: true,
        encarregado: true,
        rh: true,
        gerencia: true,
      },
    });

    if (papel !== PapelUsuario.OPERACIONAL) {
      await this.prisma.requisicaoAprovacaoUsuario.create({
        data: {
          usuarioId: usuario.id,
          papel,
          nomeCompleto: dto.nomeCompleto,
          email,
          telefone: dto.telefone,
        },
      });

      const admins = await this.prisma.usuario.findMany({
        where: { papel: PapelUsuario.ADMIN, ativo: true },
      });

      for (const admin of admins) {
        await this.prisma.notificacao.create({
          data: {
            usuarioId: admin.id,
            tipoNotificacao: 'REQUISICAO_APROVACAO',
            titulo: 'Nova requisição de aprovação',
            mensagem: `${dto.nomeCompleto} (${papel}) solicitou acesso ao sistema.`,
            urlAcao: '/admin',
          },
        });
      }

      await this.enviarEmailSolicitacaoRecebida({
        email,
        nome: dto.nomeCompleto,
        papel,
      });

      await this.enviarEmailNovaSolicitacaoParaAdmins({
        admins,
        nome: dto.nomeCompleto,
        email,
        papel,
      });

      return {
        mensagem:
          'Requisição de acesso criada. Aguarde aprovação do administrador.',
      };
    }

    await this.enviarEmailBoasVindasOperacional({
      email,
      nome: dto.nomeCompleto,
    });

    const payload = this.montarPayload(usuario);
    const accessToken = await this.jwtService.signAsync(payload);

    return {
      accessToken,
      usuario: payload,
    };
  }
}

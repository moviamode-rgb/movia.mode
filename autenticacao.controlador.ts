import { Body, Controller, Get, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import { Request, Response } from 'express';
import { AutenticacaoServico } from './autenticacao.servico';
import { EntrarDto } from './dto/entrar.dto';
import { JwtGuard } from '../../comum/guardas/jwt.guard';
import { UsuarioLogado } from '../../comum/decoradores/usuario-logado.decorator';
import { PrimeiroAcessoEstudanteDto } from './dto/primeiro-acesso-estudante.dto';
import { PrimeiroAcessoDto } from './dto/primeiro-acesso.dto';
import { BootstrapAdminDto } from './dto/bootstrap-admin.dto';
import { RecuperarSenhaDto } from './dto/recuperar-senha.dto';
import { AlterarSenhaDto } from './dto/alterar-senha.dto';

@Controller('autenticacao')
export class AutenticacaoControlador {
  constructor(private readonly servico: AutenticacaoServico) {}

  @Post('entrar')
  entrar(@Body() dto: EntrarDto, @Req() req: Request) {
    return this.servico.entrar(dto, this.obterIp(req));
  }

  @Post('primeiro-acesso-estudante')
  primeiroAcessoEstudante(@Body() dto: PrimeiroAcessoEstudanteDto) {
    return this.servico.primeiroAcessoEstudante(dto);
  }

  @Post('primeiro-acesso')
  primeiroAcesso(@Body() dto: PrimeiroAcessoDto) {
    return this.servico.primeiroAcesso(dto);
  }

  @Post('recuperar-senha')
  recuperarSenha(@Body() dto: RecuperarSenhaDto, @Req() req: Request) {
    return this.servico.recuperarSenha(dto, this.obterIp(req));
  }

  @Get('google/iniciar')
  iniciarGoogle(
    @Query('papel') papel: string,
    @Req() req: Request,
    @Res() res: Response,
  ) {
    const url = this.servico.iniciarLoginGoogle(papel, this.obterIp(req));
    return res.redirect(url);
  }

  @Get('google/callback')
  async callbackGoogle(
    @Query('code') code: string,
    @Query('state') state: string,
    @Query('error') error: string,
    @Res() res: Response,
  ) {
    const url = await this.servico.concluirLoginGoogle({ code, state, error });
    return res.redirect(url);
  }

  @UseGuards(JwtGuard)
  @Post('alterar-senha')
  alterarSenha(@UsuarioLogado() usuario: any, @Body() dto: AlterarSenhaDto) {
    return this.servico.alterarSenha(usuario.sub, dto);
  }

  @UseGuards(JwtGuard)
  @Get('2fa/status')
  status2fa(@UsuarioLogado() usuario: any) {
    return this.servico.status2fa(usuario.sub);
  }

  @UseGuards(JwtGuard)
  @Post('2fa/iniciar')
  iniciar2fa(@UsuarioLogado() usuario: any) {
    return this.servico.iniciar2fa(usuario.sub);
  }

  @UseGuards(JwtGuard)
  @Post('2fa/ativar')
  ativar2fa(@UsuarioLogado() usuario: any, @Body('codigo') codigo?: string) {
    return this.servico.ativar2fa(usuario.sub, codigo);
  }

  @UseGuards(JwtGuard)
  @Post('2fa/desativar')
  desativar2fa(
    @UsuarioLogado() usuario: any,
    @Body('senhaAtual') senhaAtual?: string,
    @Body('codigo') codigo?: string,
  ) {
    return this.servico.desativar2fa(usuario.sub, senhaAtual, codigo);
  }

  @Post('bootstrap')
  bootstrap(@Body() dto: BootstrapAdminDto) {
    return this.servico.bootstrap(dto);
  }

  @UseGuards(JwtGuard)
  @Get('eu')
  me(@UsuarioLogado() usuario: any) {
    return this.servico.me(usuario.sub);
  }

  private obterIp(req: Request) {
    const encaminhado = req.headers['x-forwarded-for'];

    if (typeof encaminhado === 'string' && encaminhado.trim()) {
      return encaminhado.split(',')[0]?.trim();
    }

    if (Array.isArray(encaminhado) && encaminhado[0]) {
      return encaminhado[0].split(',')[0]?.trim();
    }

    return req.ip || req.socket.remoteAddress || 'ip-desconhecido';
  }
}

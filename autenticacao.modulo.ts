import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PrismaService } from '../../comum/prisma.service';
import { EmailsModulo } from '../emails/emails.modulo';
import { AutenticacaoServico } from './autenticacao.servico';
import { AutenticacaoControlador } from './autenticacao.controlador';

const jwtSecret =
  process.env.JWT_CHAVE ||
  process.env.JWT_SECRET ||
  'chave_dev_sige_unica_altere_em_producao';

@Module({
  imports: [
    JwtModule.register({ secret: jwtSecret }),
    EmailsModulo,
  ],
  providers: [AutenticacaoServico, PrismaService],
  controllers: [AutenticacaoControlador],
  exports: [JwtModule],
})
export class AutenticacaoModulo {}

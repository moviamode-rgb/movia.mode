import { IsEnum, IsOptional, IsString, Length } from 'class-validator';
import { PapelUsuario } from '@prisma/client';

export class EntrarDto {
  @IsString()
  identificador!: string;

  @IsString()
  senha!: string;

  @IsOptional()
  @IsEnum(PapelUsuario)
  papel?: PapelUsuario;

  @IsOptional()
  @IsString()
  @Length(6, 6)
  codigo2fa?: string;
}

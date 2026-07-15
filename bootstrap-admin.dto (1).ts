import { IsEmail, IsIn, IsOptional, IsString, Length } from 'class-validator';

export class BootstrapAdminDto {
  @IsString()
  secret!: string;

  @IsIn(['RH'])
  papel!: 'RH';

  @IsString()
  nomeCompleto!: string;

  @IsString()
  matriculaServidor!: string;

  @IsEmail()
  email!: string;

  @IsString()
  @Length(6, 60)
  senha!: string;

  @IsOptional()
  @IsString()
  setor?: string;
}

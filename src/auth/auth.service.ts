import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs'
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto, CreateUserDto, UpdateAuthDto, LoginDto } from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) {

  }

  async create(createUserDto: CreateUserDto): Promise<User> {
    // console.log(createUserDto);

    try {

      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        ...userData, password: bcryptjs.hashSync(password, 10)
      });
      // 1- Encriptar la contraseña

      // 2- Guardar el usuario en la base de datos

      // 3- Generar el JWT


      await newUser.save();
      const { password: _, ...user } = newUser.toJSON();
      return user;

    } catch (error) {
      //console.log(error.code);
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists.`)
      }
      throw new InternalServerErrorException('Something terrible happen!!!')
    }

  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {
    //console.log({ loginDto });
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new UnauthorizedException('Not valid credentials - email ');
    }
    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credentials - password');
    }

    const { password: _, ...rest } = user.toJSON();
    return {
      user: rest,
      token: this.getJwtToken({ id: user.id })
    }
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {
    //console.log({ loginDto });
    const user = await this.create(registerUserDto);
    console.log(user);

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    }
  }


  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}

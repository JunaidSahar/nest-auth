/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable prettier/prettier */
/* eslint-disable @typescript-eslint/no-unsafe-call */
import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from 'generated/prisma/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: AuthDto) {
    try {
      // generate the password hash
      const userHash = await argon.hash(dto.password);
      
      // save the new user in the db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash: userHash,
        },
      });

      // remove hash before returning
      const { hash, ...userWithoutHash } = user;
      return userWithoutHash;
      
    } catch (error) {
      throw new ForbiddenException('Email already exists', error.code);
    }
  }

  async signin(dto: AuthDto) {
    // find the user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });

    // if user not found throw exception
    if (!user) {
      throw new ForbiddenException('Account with this email does not exist');
    }

    // compare password hash
    const passwordMatches = await argon.verify(user.hash, dto.password);

    // if password does not match throw exception
    if (!passwordMatches) {
      throw new ForbiddenException('Password is incorrect');
    }

    // remove hash before returning
    const { hash, ...userWithoutHash } = user;
    return userWithoutHash;
  }
}

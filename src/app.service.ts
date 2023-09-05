import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppService {
  constructor(private configService: ConfigService) {
    const USERNAME = this.configService.get('config.database.username');
    const PASSWORD = this.configService.get('config.database.password');
    console.log('===> USERNAME:', USERNAME);
    console.log('===> PASSWORD:', PASSWORD);
  }

  getHello(): string {
    return 'Hello World!';
  }
}

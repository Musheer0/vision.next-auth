import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { ThrottlerModule } from '@nestjs/throttler';
import KeyvRedis, { createKeyv } from '@keyv/redis';
import { Keyv } from 'keyv';
import { CacheableMemory } from 'cacheable';

import { CacheModule } from '@nestjs/cache-manager';
@Module({
  imports: [PrismaModule, AuthModule,
    ThrottlerModule.forRoot({
      throttlers:[
        {ttl:60000,
        limit:2
      }
      ]
    }),
   CacheModule.registerAsync({
    isGlobal:true,
      useFactory: async () => {
        return {
          stores: [
             new Keyv(new KeyvRedis('redis://localhost:6379')), // ✅ Redis is first (Primary)
        new Keyv({ store: new CacheableMemory({ ttl: 60000, lruSize: 5000 }) }), // 🛟 Memory fallback
          ],
        };
      },
    }),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}

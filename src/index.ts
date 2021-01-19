import { Module } from '@shattercms/types';
import { User } from './entities';
import { UserResolver } from './resolvers';
import { scopeHandler, validHandler } from './auth/handlers';
export * from './entities';
export * from './resolvers';
export * from './auth/handlers';

const usersModule: Module = (context) => {
  context.entities.push(User);
  context.resolvers.push(UserResolver);
  context.authHandlers.push(...[scopeHandler, validHandler]);
};
export default usersModule;

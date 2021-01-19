import jwt from 'jsonwebtoken';

export const sign = (
  secret: string,
  payload: any,
  type: 'access' | 'refresh'
) => {
  if (!secret) {
    console.log('Failed to sign, there was no secret key assigned');
    return;
  }

  try {
    const token = jwt.sign(
      {
        $t: type, // Pass token type
        ...payload,
      },
      secret,
      {
        algorithm: 'RS512',
        expiresIn: type === 'access' ? '10m' : '1y',
      }
    );
    return token;
  } catch (error) {
    console.log(error);
    return;
  }
};

export const verify = (
  secret: string,
  token: string,
  type?: 'access' | 'refresh'
) => {
  if (!secret) {
    console.log('Failed to verify, there was no secret key assigned');
    return;
  }

  try {
    const payload = jwt.verify(token, secret, {
      algorithms: ['RS512'],
    }) as { [key: string]: any };
    if (type && type !== payload.$t) {
      console.log('Failed to verify, unexpected token type');
      return;
    }
    return payload;
  } catch (error) {
    console.log(error);
    return;
  }
};

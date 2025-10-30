// Tuvimos que setear esto aca sino los tests fallaban por no encontrar la variable
process.env.JWT_SECRET = 'test-secret-key';

import nodemailer from 'nodemailer';

import AuthService from '../../src/services/authService';
import jwtUtil from '../../src/utils/jwt';
import db from '../../src/db';
import { User } from '../../src/types/user';

jest.mock('../../src/db')
const mockedDb = db as jest.MockedFunction<typeof db>

// mock the nodemailer module
jest.mock('nodemailer');
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

// mock send email function
mockedNodemailer.createTransport = jest.fn().mockReturnValue({
  sendMail: jest.fn().mockResolvedValue({ success: true }),
});

describe('AuthService.generateJwt', () => {
  const OLD_ENV = process.env;
  beforeEach (() => {
    jest.resetModules();
    jest.clearAllMocks();

  });

  it('createUser', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: 'Last',
      username: 'username',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null) // No existing user
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
    .mockReturnValueOnce(selectChain as any)
    .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    // Verify the database calls
    expect(insertChain.insert).toHaveBeenCalledWith({
      email: user.email,
      password: user.password,
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      activated: false,
      invite_token: expect.any(String),
      invite_token_expires: expect.any(Date)
    });

    expect(nodemailer.createTransport).toHaveBeenCalled();
    expect(nodemailer.createTransport().sendMail).toHaveBeenCalledWith(expect.objectContaining({
      from: "info@example.com",
      to: user.email,
      subject: 'Activate your account',
      html: expect.stringContaining('Click <a href=')
    }));
  }
  );

  it('createUser already exist', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: 'Last',
      username: 'username',
    } as User;
    // mock user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(user) // Existing user found
    };
    mockedDb.mockReturnValueOnce(selectChain as any);
    // Call the method to test
    await expect(AuthService.createUser(user)).rejects.toThrow('User already exists with that username or email');
  });

  it('updateUser', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@b.com',
      password: 'newpassword123',
      first_name: 'NewFirst',
      last_name: 'NewLast',
      username: 'newusername',
    } as User;
    // mock user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({ id: user.id }) // Existing user found
    };
    // Mock the database update
    const updateChain = {
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue(user) // Update successful
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(updateChain as any);
    // Call the method to test
    const updatedUser = await AuthService.updateUser(user);
    // Verify the database calls
    expect(selectChain.where).toHaveBeenCalledWith({ id: user.id });
    expect(updateChain.update).toHaveBeenCalled();
  });

  it('updateUser not found', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: 'Last',
      username: 'username',
    } as User;
    // mock user not found
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null) // No existing user found
    };
    mockedDb.mockReturnValueOnce(selectChain as any);
    // Call the method to test
    await expect(AuthService.updateUser(user)).rejects.toThrow('User not found');
  });

  it('authenticate', async () => {
    const email = 'username';
    const password = 'password123';

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({password}),
    };
    // Mock the database update password
    mockedDb.mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    const user = await AuthService.authenticate(email, password);
    expect(getUserChain.where).toHaveBeenCalledWith({username : 'username'});
    expect(user).toBeDefined();
  });

  it('authenticate wrong pass', async () => {

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({password:'otherpassword'}),
    };
    // Mock the database update password
    mockedDb.mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    await expect(AuthService.authenticate('username', 'password123')).rejects.toThrow('Invalid password');
  });

  it('authenticate wrong user', async () => {

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    // Mock the database update password
    mockedDb.mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    await expect(AuthService.authenticate('username', 'password123')).rejects.toThrow('Invalid username or not activated');
  });

  it('sendResetPasswordEmail', async () => {
    const email = 'a@a.com';
    const user = {
      id: 'user-123',
      email: email,
    };
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(user),
    };
    // Mock the database update password
    const updateChain = {
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue(1)
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any)
      .mockReturnValueOnce(updateChain as any); 
    // Call the method to test
    await AuthService.sendResetPasswordEmail(email);
    expect(getUserChain.where).toHaveBeenCalledWith({ email });
    expect(updateChain.update).toHaveBeenCalledWith({
      reset_password_token: expect.any(String),
      reset_password_expires: expect.any(Date)
    });
    expect(mockedNodemailer.createTransport).toHaveBeenCalled();
    expect(mockedNodemailer.createTransport().sendMail).toHaveBeenCalledWith({
      to: user.email,
      subject: 'Your password reset link',
      html: expect.stringContaining('Click <a href="')
    });
  });

  it('sendResetPasswordEmail no mail', async () => {
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };

    mockedDb
      .mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    await expect(AuthService.sendResetPasswordEmail('a@a.com')).rejects.toThrow('No user with that email or not activated');
  });

  it('resetPassword', async () => {
    const token = 'valid-token';
    const newPassword = 'newpassword123';    
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({id: 'user-123'}),
    };
    // Mock the database update password
    const updateChain = {
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue(1)
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any)
      .mockReturnValueOnce(updateChain as any);
    // Call the method to test
    await AuthService.resetPassword(token, newPassword);
    expect(getUserChain.where).toHaveBeenCalledWith('reset_password_token', token);
    expect(updateChain.update).toHaveBeenCalledWith({
      password: newPassword,
      reset_password_token: null,
      reset_password_expires: null
    });
  });

  it('resetPassword invalid token', async () => {
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any);
    // Call the method to test
    await expect(AuthService.resetPassword('invalid-token', 'newpassword123')).rejects.toThrow('Invalid or expired reset token');
  });

  it('setInitialPassword', async () => {
    const password = 'whatawonderfulpassword';
    const user_id = 'user-123';
    const token = 'invite-token';
    // Mock the database row
    const mockRow = {
      id: user_id,
      invite_token: token,
      invite_token_expires: new Date(Date.now() + 1000 * 60 * 60 * 24) // 1 day from now
    };

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(mockRow),
    };

    // mock the database update password
    const updateChain = {
      where: jest.fn().mockResolvedValue(1),
      update: jest.fn().mockReturnThis()
    }

    mockedDb
      .mockReturnValueOnce(getUserChain as any)
      .mockReturnValueOnce(updateChain as any);

    // Call the method to test
    await AuthService.setPassword(token, password);

    // Verify the database calls
    expect(updateChain.update).toHaveBeenCalledWith({
      password: password,
      invite_token: null,
      invite_token_expires: null,
      activated:true
    });

    expect(updateChain.where).toHaveBeenCalledWith({ id: user_id });
  });

  it('setInitialPassword invalid token', async () => {
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any);
    // Call the method to test
    await expect(AuthService.setPassword('invalid-token', 'newpassword123')).rejects.toThrow('Invalid or expired invite token');
  });

  it('generateJwt', () => {
    const userId = 'abcd-1234';
    const token = AuthService.generateJwt(userId);

    // token should be a non-empty string
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);

    // verify the token decodes to our payload
    const decoded = jwtUtil.verifyToken(token);
    expect((decoded as any).id).toBe(userId);
  });


  // TEST TEMPLATE INJECTION 
  //npm test -- authService.test.ts -t "test 1"
  //npm test -- authService.test.ts -t "test 2"
  //npm test -- authService.test.ts -t "test 3"
  //npm test -- authService.test.ts -t "test 4"
  //npm test -- authService.test.ts -t "test 5"
  //npm test -- authService.test.ts -t "test 6"
  // Estos test estan todos mitigados, asi que corren los 6 sin problema.

  // Hay unos test generados por ustedes que son de unas contraseñas, que nosotros
  // agregamos un sistema de hashing de contraseñas, por lo que esos test fallan.
  // Se nos fue comentado que esos no debiamos de tocarlos.

  // https://www.vaadata.com/blog/server-side-template-injection-vulnerability-what-it-is-how-to-prevent-it
  // De esta pagina web obtuvimos ideas para generar los test de template injection.

  // Test 1: Verifica que el template injection con sintaxis EJS sea mitigado
  // Prueba con expresión matemática simple <%= 7*7 %> que debería resultar en 49 si se ejecuta
  it('createUser - test 1', async () => {
    const user = {
      id: 'user-123',
      email: 'test@test.com',
      password: 'password123',
      first_name: '<%= 7*7 %>',
      last_name: 'Last',
      username: 'testuser',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    const sendMailCall = (nodemailer.createTransport().sendMail as jest.Mock).mock.calls[0][0];
    expect(sendMailCall.html).toContain('&lt;%= 7*7 %&gt;');
  });

  // Test 2: Verifica que el template injection con sintaxis EJS en last_name sea mitigado
  // Prueba con expresión matemática simple <%= 7*7 %> en last_name
  it('createUser - test 2', async () => {
    const user = {
      id: 'user-456',
      email: 'test2@test.com',
      password: 'password123',
      first_name: 'First',
      last_name: '<%= 7*7 %>',
      username: 'testuser2',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    const sendMailCall = (nodemailer.createTransport().sendMail as jest.Mock).mock.calls[0][0];
    expect(sendMailCall.html).toContain('&lt;%= 7*7 %&gt;');
  });

  // Test 3: Verifica que el template injection con sintaxis EJS en ambos campos sea mitigado
  // Prueba con expresión matemática simple <%= 7*7 %> en first_name y last_name
  it('createUser - test 3', async () => {
    const user = {
      id: 'user-789',
      email: 'test3@test.com',
      password: 'password123',
      first_name: '<%= 7*7 %>',
      last_name: '<%= 7*7 %>',
      username: 'testuser3',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    const sendMailCall = (nodemailer.createTransport().sendMail as jest.Mock).mock.calls[0][0];
    expect(sendMailCall.html).toContain('&lt;%= 7*7 %&gt;');
  });

  // Test 4: Verifica que el template injection con sintaxis de plantillas JavaScript sea mitigado
  // Prueba con ${7*7} que es común en template strings de JavaScript
  it('createUser - test 4', async () => {
    const user = {
      id: 'user-456',
      email: 'test4@test.com',
      password: 'password123',
      first_name: 'First',
      last_name: '${7*7}',
      username: 'testuser4',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    const sendMailCall = (nodemailer.createTransport().sendMail as jest.Mock).mock.calls[0][0];
    expect(sendMailCall.html).toContain('${7*7}');
  });

  // Test 5: Verifica que el template injection con múltiples sintaxis sea mitigado
  // Prueba con {{7*7}} (Handlebars/Mustache) y #{7*7} (Ruby ERB style)
  it('createUser - test 5', async () => {
    const user = {
      id: 'user-789',
      email: 'test5@test.com',
      password: 'password123',
      first_name: '{{7*7}}',
      last_name: '#{7*7}',
      username: 'testuser5',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    const sendMailCall = (nodemailer.createTransport().sendMail as jest.Mock).mock.calls[0][0];
    expect(sendMailCall.html).toContain('{{7*7}}');
    expect(sendMailCall.html).toContain('#{7*7}'); 
  });

  // Test 6: Verifica que el contenido seguro se renderice correctamente en el template
  // Confirma que datos normales de usuario se procesen sin problemas en el email
  it('createUser - test 6', async () => {
    const user = {
      id: 'user-456',
      email: 'pedro@test.com',
      password: 'password123',
      first_name: 'Pedro',
      last_name: 'Picapiedra',
      username: 'pedropica',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    const sendMailCall = (nodemailer.createTransport().sendMail as jest.Mock).mock.calls[0][0];
    expect(sendMailCall.html).toContain('<h1>Hello Pedro Picapiedra</h1>');
    expect(sendMailCall.html).toContain('Click <a href=');
    expect(sendMailCall.html).toContain('activate-user?token=');
  });

});

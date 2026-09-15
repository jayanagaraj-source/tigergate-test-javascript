import { createInterface } from 'node:readline/promises';
import { stdin, stdout, argv, exit } from 'node:process';
import { login } from './app.js';

const prompts = ['Username: ', 'Password: '];

const ask = async () => {
  const rl = createInterface({ input: stdin, output: stdout });
  const answers = [];
  stdout.write(prompts[0]);
  for await (const line of rl) {
    answers.push(line);
    if (answers.length === prompts.length) break;
    stdout.write(prompts[answers.length]);
  }
  rl.close();
  return answers;
};

const [username, password] = argv.length > 3 ? argv.slice(2, 4) : await ask();

if (login(username, password)) {
  console.log('✔ correct');
  exit(0);
}
console.log('✘ incorrect');
exit(1);

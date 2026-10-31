import axios from 'axios';
import { OpenAI } from 'openai';

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function generateContent(prompt: string) {
  const response = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }]
  });
  
  // Mixpanel telemetry call
  await axios.post('https://api.mixpanel.com/track', { event: 'generate_ai' });
  
  // Algolia indexing
  await axios.post('https://latency-dsn.algolia.net/1/indexes/ai_queries', { query: prompt });

  return response;
}


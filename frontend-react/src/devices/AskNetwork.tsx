import { useState } from 'react';
import { useMutation } from '@tanstack/react-query';
import { askNetwork } from './api';
import { formatNumber } from '../utils/format';
import { getLocale } from '../utils/i18n';

export default function AskNetwork() {
  const [question, setQuestion] = useState('');

  const mutation = useMutation({
    mutationFn: (q: string) => askNetwork(q, getLocale()),
  });

  const handleSubmit = () => {
    if (question.trim().length < 5) return;
    mutation.mutate(question.trim());
  };

  const data = mutation.data;
  const tok = data?.tokens || {};
  const totalCost = (tok.prompt_tokens || 0) * 0.10 / 1e6 + (tok.response_tokens || 0) * 0.40 / 1e6;
  const costLabel = totalCost >= 0.01 ? `${(totalCost * 100).toFixed(2)}¢` : `${(totalCost * 1000).toFixed(3)}m¢`;

  return (
    <div className="bg-white dark:bg-white/[0.03] border border-slate-200 dark:border-white/[0.05] rounded-xl px-4 py-3">
      <div className="flex items-center gap-2">
        <i className="ph-duotone ph-sparkle text-lg text-indigo-500 flex-shrink-0" />
        <input
          type="text"
          placeholder="Ask anything about your network..."
          value={question}
          onChange={e => setQuestion(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') handleSubmit(); }}
          className="flex-1 bg-transparent text-sm text-slate-700 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-500 outline-none"
        />
        <button
          onClick={handleSubmit}
          disabled={mutation.isPending || question.trim().length < 5}
          className="flex-shrink-0 px-3 py-1.5 rounded-lg bg-gradient-to-r from-indigo-500 to-purple-500 hover:from-indigo-600 hover:to-purple-600 text-white text-xs font-semibold shadow-sm transition-all active:scale-95 disabled:opacity-50"
        >
          {mutation.isPending ? <i className="ph-duotone ph-circle-notch animate-spin" /> : 'Ask'}
        </button>
      </div>

      {mutation.isPending && (
        <div className="mt-3 pt-3 border-t border-slate-100 dark:border-white/[0.05]">
          <div className="flex items-center gap-2 text-indigo-500 py-2">
            <i className="ph-duotone ph-circle-notch animate-spin text-lg" />
            <span className="text-sm">Analyzing your network...</span>
          </div>
        </div>
      )}

      {mutation.isError && (
        <div className="mt-3 pt-3 border-t border-slate-100 dark:border-white/[0.05]">
          <p className="text-sm text-red-500">{(mutation.error as Error)?.message}</p>
        </div>
      )}

      {data && !mutation.isPending && (
        <div className="mt-3 pt-3 border-t border-slate-100 dark:border-white/[0.05]">
          <div
            className="prose prose-sm dark:prose-invert max-w-none text-sm leading-relaxed text-slate-700 dark:text-slate-300"
            dangerouslySetInnerHTML={{ __html: renderMarkdown(data.answer || '') }}
          />
          <div className="mt-3 pt-2 border-t border-slate-100 dark:border-white/[0.05] flex items-center justify-between text-[10px] text-slate-400 dark:text-slate-500">
            <span>{data.model || ''} · {formatNumber(tok.total_tokens || 0)} tokens · {data.elapsed_s || '?'}s</span>
            <span>{costLabel}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function renderMarkdown(md: string): string {
  if (!md) return '';
  return md
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/^### (.+)$/gm, '<h4 class="text-sm font-semibold mt-4 mb-1">$1</h4>')
    .replace(/^## (.+)$/gm, '<h3 class="text-base font-semibold mt-5 mb-2">$1</h3>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g, '<em>$1</em>')
    .replace(/`([^`]+)`/g, '<code class="px-1 py-0.5 rounded bg-slate-200/70 dark:bg-slate-700/50 text-xs font-mono">$1</code>')
    .replace(/^- (.+)$/gm, '<li class="ml-4 list-disc text-sm">$1</li>')
    .replace(/\n\n/g, '</p><p class="mb-2">')
    .replace(/\n/g, '<br>');
}

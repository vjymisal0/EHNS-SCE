interface IndicatorsListProps {
  indicators: string[];
}

export default function IndicatorsList({ indicators }: IndicatorsListProps) {
  return (
    <div>
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-gray-400">
        Suspicious Indicators
      </h3>

      {indicators.length === 0 ? (
        <div className="rounded-lg bg-gray-900/80 p-4 ring-1 ring-gray-800 text-center">
          <div className="mx-auto mb-2 flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/10">
            <svg
              className="h-5 w-5 text-emerald-400"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>
          <p className="text-sm text-gray-400">No suspicious indicators found</p>
        </div>
      ) : (
        <ul className="space-y-2">
          {indicators.map((indicator, i) => (
            <li
              key={i}
              className="flex items-start gap-3 rounded-lg bg-red-500/5 p-3 ring-1 ring-red-500/20"
            >
              <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-red-500/20">
                <svg
                  className="h-3 w-3 text-red-400"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
                  />
                </svg>
              </span>
              <span className="text-sm text-red-300">{indicator}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

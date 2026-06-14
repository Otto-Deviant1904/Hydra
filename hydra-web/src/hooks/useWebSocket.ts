import { useCallback, useEffect, useRef, useState } from 'react'

export type WebSocketStatus = 'connecting' | 'open' | 'closed' | 'error'

export interface UseWebSocketOptions {
  /** Called when a message is received. */
  onMessage?: (event: MessageEvent) => void
  /** Called when the connection opens. */
  onOpen?: (event: Event) => void
  /** Called when the connection closes. */
  onClose?: (event: CloseEvent) => void
  /** Called on a connection error. */
  onError?: (event: Event) => void
  /**
   * Whether to automatically reconnect on disconnect.
   * Defaults to true.
   */
  reconnect?: boolean
  /**
   * Initial delay (ms) before the first reconnect attempt.
   * Subsequent attempts use exponential backoff up to `maxDelay`.
   * Defaults to 1000.
   */
  initialDelay?: number
  /** Maximum reconnect delay in ms. Defaults to 30 000. */
  maxDelay?: number
  /** Maximum number of reconnect attempts (0 = unlimited). Defaults to 0. */
  maxRetries?: number
}

export interface UseWebSocketReturn {
  status: WebSocketStatus
  retryCount: number
  send: (data: string | ArrayBufferLike | Blob | ArrayBufferView) => void
  disconnect: () => void
  reconnectNow: () => void
}

/**
 * Hook that manages a WebSocket connection with automatic exponential-backoff
 * reconnection on disconnect or error.
 *
 * @param url - WebSocket URL to connect to, or null/undefined to stay disconnected.
 * @param options - Configuration options.
 */
export function useWebSocket(
  url: string | null | undefined,
  options: UseWebSocketOptions = {},
): UseWebSocketReturn {
  const {
    onMessage,
    onOpen,
    onClose,
    onError,
    reconnect = true,
    initialDelay = 1000,
    maxDelay = 30_000,
    maxRetries = 0,
  } = options

  const [status, setStatus] = useState<WebSocketStatus>('closed')
  const [retryCount, setRetryCount] = useState(0)

  const wsRef = useRef<WebSocket | null>(null)
  const retryCountRef = useRef(0)
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const intentionalCloseRef = useRef(false)

  // Keep callbacks in refs so the connect closure doesn't go stale.
  const onMessageRef = useRef(onMessage)
  const onOpenRef = useRef(onOpen)
  const onCloseRef = useRef(onClose)
  const onErrorRef = useRef(onError)
  useEffect(() => { onMessageRef.current = onMessage }, [onMessage])
  useEffect(() => { onOpenRef.current = onOpen }, [onOpen])
  useEffect(() => { onCloseRef.current = onClose }, [onClose])
  useEffect(() => { onErrorRef.current = onError }, [onError])

  const clearRetryTimer = useCallback(() => {
    if (retryTimerRef.current !== null) {
      clearTimeout(retryTimerRef.current)
      retryTimerRef.current = null
    }
  }, [])

  const connect = useCallback(() => {
    if (!url) return

    // Clean up any existing socket before opening a new one.
    // Null out onclose first to prevent the close event from triggering a
    // spurious reconnect: intentionalCloseRef would already be reset to false
    // by the time the async close event fires on the old socket.
    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.close()
      wsRef.current = null
    }
    intentionalCloseRef.current = false
    setStatus('connecting')

    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = (event) => {
      retryCountRef.current = 0
      setRetryCount(0)
      setStatus('open')
      onOpenRef.current?.(event)
    }

    ws.onmessage = (event) => {
      onMessageRef.current?.(event)
    }

    ws.onerror = (event) => {
      setStatus('error')
      onErrorRef.current?.(event)
    }

    ws.onclose = (event) => {
      wsRef.current = null
      setStatus('closed')
      onCloseRef.current?.(event)

      if (intentionalCloseRef.current || !reconnect) return
      if (maxRetries > 0 && retryCountRef.current >= maxRetries) return

      const attempt = retryCountRef.current + 1
      retryCountRef.current = attempt
      setRetryCount(attempt)

      // Exponential backoff with jitter: delay * 2^(attempt-1), capped at maxDelay.
      const baseDelay = Math.min(initialDelay * Math.pow(2, attempt - 1), maxDelay)
      const jitter = Math.random() * 0.3 * baseDelay
      const delay = Math.round(baseDelay + jitter)

      retryTimerRef.current = setTimeout(() => {
        connect()
      }, delay)
    }
  }, [url, reconnect, initialDelay, maxDelay, maxRetries]) // eslint-disable-line react-hooks/exhaustive-deps

  // Connect/disconnect when url changes.
  useEffect(() => {
    if (!url) return
    connect()
    return () => {
      clearRetryTimer()
      intentionalCloseRef.current = true
      wsRef.current?.close()
      wsRef.current = null
    }
  }, [url]) // eslint-disable-line react-hooks/exhaustive-deps

  const send = useCallback(
    (data: string | ArrayBufferLike | Blob | ArrayBufferView) => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(data)
      }
    },
    [],
  )

  const disconnect = useCallback(() => {
    clearRetryTimer()
    intentionalCloseRef.current = true
    wsRef.current?.close()
    wsRef.current = null
    setStatus('closed')
  }, [clearRetryTimer])

  const reconnectNow = useCallback(() => {
    clearRetryTimer()
    connect()
  }, [clearRetryTimer, connect])

  return { status, retryCount, send, disconnect, reconnectNow }
}

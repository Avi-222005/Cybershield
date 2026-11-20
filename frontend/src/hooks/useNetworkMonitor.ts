import { useCallback, useEffect, useRef, useState } from 'react'
import {
  getNetworkSummary,
  getNetworkInterfaces,
  startMonitoring,
  stopMonitoring,
} from '../services/networkMonitorService'
import type {
  NetworkSummary,
  NetworkInterface,
  TrafficDataPoint,
} from '../types/networkMonitor'

const MAX_HISTORY_POINTS = 60

export function useNetworkMonitor() {
  const [summary, setSummary] = useState<NetworkSummary | null>(null)
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([])
  const [trafficHistory, setTrafficHistory] = useState<TrafficDataPoint[]>([])
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [isStarting, setIsStarting] = useState<boolean>(false)
  const [isStopping, setIsStopping] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const isMountedRef = useRef(true)
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const isFetchingRef = useRef(false)

  // Fetch interface list
  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await getNetworkInterfaces()
      if (isMountedRef.current && res.success) {
        setInterfaces(res.interfaces)
      }
    } catch (err: any) {
      // Interface fetch fail is non-fatal
      console.warn('Failed to load interfaces:', err?.message)
    }
  }, [])

  // Poll summary
  const fetchSummary = useCallback(async () => {
    if (isFetchingRef.current) return
    isFetchingRef.current = true

    try {
      const res = await getNetworkSummary()
      if (!isMountedRef.current) return

      if (res.success && res.summary) {
        const s = res.summary
        setSummary(s)
        setLastUpdated(new Date())
        setError(null)

        // Append to traffic history if running
        if (s.status.state === 'RUNNING' && s.traffic) {
          const now = new Date()
          const timeStr = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
          const downMbps = s.traffic.download_mbps || 0
          const upMbps = s.traffic.upload_mbps || 0
          const downKBps = s.traffic.download_bytes_per_sec ? s.traffic.download_bytes_per_sec / 1024 : 0
          const upKBps = s.traffic.upload_bytes_per_sec ? s.traffic.upload_bytes_per_sec / 1024 : 0

          setTrafficHistory((prev) => {
            const next = [
              ...prev,
              {
                time: timeStr,
                timestamp: now.getTime(),
                downloadMbps: Number(downMbps.toFixed(4)),
                uploadMbps: Number(upMbps.toFixed(4)),
                downloadKBps: Number(downKBps.toFixed(1)),
                uploadKBps: Number(upKBps.toFixed(1)),
              },
            ]
            return next.slice(-MAX_HISTORY_POINTS)
          })
        }
      }
    } catch (err: any) {
      if (isMountedRef.current) {
        setError(err?.message || 'Failed to communicate with network monitoring service.')
      }
    } finally {
      if (isMountedRef.current) {
        setIsLoading(false)
        isFetchingRef.current = false
      }
    }
  }, [])

  // Start monitoring action
  const handleStart = useCallback(
    async (interfaceName?: string, forceAdapter?: string) => {
      setIsStarting(true)
      setError(null)
      try {
        const res = await startMonitoring(interfaceName, forceAdapter)
        if (res.success) {
          await fetchSummary()
          await fetchInterfaces()
        } else {
          setError(res.error || 'Failed to start monitoring')
        }
      } catch (err: any) {
        setError(err?.message || 'Error communicating with backend.')
      } finally {
        if (isMountedRef.current) setIsStarting(false)
      }
    },
    [fetchSummary, fetchInterfaces]
  )

  // Stop monitoring action
  const handleStop = useCallback(async () => {
    setIsStopping(true)
    setError(null)
    try {
      const res = await stopMonitoring()
      if (res.success) {
        await fetchSummary()
      } else {
        setError(res.error || 'Failed to stop monitoring')
      }
    } catch (err: any) {
      setError(err?.message || 'Error stopping monitoring.')
    } finally {
      if (isMountedRef.current) setIsStopping(false)
    }
  }, [fetchSummary])

  // Initial load
  useEffect(() => {
    isMountedRef.current = true
    fetchInterfaces()
    fetchSummary()

    return () => {
      isMountedRef.current = false
    }
  }, [fetchInterfaces, fetchSummary])

  // Polling loop
  useEffect(() => {
    const isRunning = summary?.status.state === 'RUNNING'
    const intervalMs = isRunning ? 1000 : 4000

    const schedulePoll = () => {
      if (timerRef.current) clearInterval(timerRef.current)
      timerRef.current = setInterval(() => {
        if (document.visibilityState === 'visible') {
          fetchSummary()
        }
      }, intervalMs)
    }

    schedulePoll()

    const handleVisibility = () => {
      if (document.visibilityState === 'visible') {
        fetchSummary()
        schedulePoll()
      }
    }

    document.addEventListener('visibilitychange', handleVisibility)

    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
      document.removeEventListener('visibilitychange', handleVisibility)
    }
  }, [summary?.status.state, fetchSummary])

  return {
    summary,
    interfaces,
    trafficHistory,
    isLoading,
    isStarting,
    isStopping,
    error,
    lastUpdated,
    start: handleStart,
    stop: handleStop,
    refresh: fetchSummary,
    reloadInterfaces: fetchInterfaces,
  }
}

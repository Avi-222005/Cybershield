import { motion, type HTMLMotionProps } from 'framer-motion'
import { ReactNode } from 'react'

interface PageWrapperProps extends HTMLMotionProps<'div'> {
  children: ReactNode
  className?: string
}

export default function PageWrapper({ children, className = '', ...rest }: PageWrapperProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 18 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -18 }}
      transition={{ duration: 0.28, ease: 'easeInOut' }}
      className={className}
      {...rest}
    >
      {children}
    </motion.div>
  )
}

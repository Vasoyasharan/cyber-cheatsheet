import { useEffect, useState } from 'react';
import { motion, useAnimation } from 'framer-motion';

export const useScrollAnimation = (ref, threshold = 0.1) => {
  const controls = useAnimation();
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          controls.start('visible');
          setIsVisible(true);
        }
      },
      { threshold }
    );

    if (ref.current) {
      observer.observe(ref.current);
    }

    return () => {
      if (ref.current) {
        observer.unobserve(ref.current);
      }
    };
  }, [ref, controls, threshold]);

  return [controls, isVisible];
};

export const useHoverAnimation = () => {
  const [isHovered, setIsHovered] = useState(false);
  const controls = useAnimation();

  useEffect(() => {
    if (isHovered) {
      controls.start({
        scale: 1.05,
        boxShadow: '0 10px 20px rgba(0,0,0,0.2)',
        transition: { duration: 0.3 }
      });
    } else {
      controls.start({
        scale: 1,
        boxShadow: '0 5px 15px rgba(0,0,0,0.1)',
        transition: { duration: 0.3 }
      });
    }
  }, [isHovered, controls]);

  return {
    animate: controls,
    onHoverStart: () => setIsHovered(true),
    onHoverEnd: () => setIsHovered(false)
  };
};
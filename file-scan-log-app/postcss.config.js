import tailwindcss from '@tailwindcss/postcss';
import autoprefixer from 'autoprefixer';
import nesting from 'postcss-nesting';
import cssnano from 'cssnano';
import postcssPresetEnv from 'postcss-preset-env';

const isProduction = process.env.NODE_ENV === 'production';

export default {
  plugins: [
    tailwindcss(),
    autoprefixer(),
    nesting(),
    postcssPresetEnv({
      stage: 1,
      features: {
        'nesting-rules': true,
        'custom-properties': true,
      },
    }),
    ...(isProduction
      ? [cssnano({ preset: 'default' })]
      : []),
  ],
};
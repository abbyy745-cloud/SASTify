const vueParser = require('vue-eslint-parser');
const fs = require('fs');

const code = `<template>
  <div>
    <h1>Vue Vulnerability</h1>
    <!-- Vulnerability: v-html XSS -->
    <div v-html="userContent"></div>
  </div>
</template>

<script>
export default {
  data() {
    return {
      userContent: '<script>alert(1)</script>'
    }
  }
}
</script>`;

try {
    const ast = vueParser.parse(code, {
        sourceType: 'module',
        ecmaVersion: 2020,
        parser: 'espree'
    });
    console.log("Success!");
    console.log(JSON.stringify(ast, null, 2));
} catch (e) {
    console.error("Error:", e.message);
}

<template>
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
      userContent: '<img src=x onerror=alert(1)>'
    }
  }
}
</script>

module.exports = function(grunt) {
  
  // Config
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    jshint: {
      files: [ 'Gruntfile.js', 'src/**/*.js', 'test/**/*.js']
    },
    mochaTest: {
      test: {
        options: {
          reporter: 'spec',
          quiet: false,
          clearRequireCache: false
        },
        src: ['test/**/*.js']
      }
    },
    watch: {
      scripts: {
        files: ['<%= jshint.files %>'],
        tasks: ['jshint', 'mochaTest'],
        options: {
          deboundeDelay: 10000
        }
      } 
    }
  });

  // Plugins
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-contrib-watch');

  // Register Tasks
  grunt.registerTask('default', ['mochaTest', 'jshint']);
  grunt.registerTask('test', ['mochaTest']);
};
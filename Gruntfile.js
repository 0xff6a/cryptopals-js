module.exports = function(grunt) {
  
  // Config
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    jshint: {
      files: [ 'Gruntfile.js', 'src/**/*.js', 'test/**/*.js']
    },
    run: {
       hmacApp: {
         options: {
           wait: false
         },
         // cmd: "node", // but that's the default 
         args: [
          'src/hmacApp.js'
        ]
      }
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
  grunt.loadNpmTasks('grunt-run');

  // Register Tasks
  grunt.registerTask('default', [ 'run:hmacApp', 'mochaTest', 'jshint']);
  grunt.registerTask('test', ['run:hmacApp', 'mochaTest']);
};
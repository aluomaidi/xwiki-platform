/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
/*!
#set ($liveDataEntry = 'xwiki-livedata.umd.min')
#set ($liveDataPath = $services.webjars.url('org.xwiki.platform:xwiki-platform-livedata-webjar', $liveDataEntry))
#set ($paths = {
  'js': {
    'Logic': $services.webjars.url('org.xwiki.platform:xwiki-platform-livedata-webjar', 'Logic.min'),
    'liveDataSource': $services.webjars.url('org.xwiki.platform:xwiki-platform-livedata-webjar',
      'liveDataSource.min.js', {'evaluate': true}),
    'Vue': $services.webjars.url('vue', 'vue.min'),
    'xwiki-livedata': $liveDataPath,
    'moment': $services.webjars.url('momentjs', 'moment.js'),
    'daterangepicker': $services.webjars.url('bootstrap-daterangepicker', 'js/bootstrap-daterangepicker.js'),
    'xwiki-selectize': $xwiki.getSkinFile('uicomponents/suggest/xwiki.selectize.js', true)
  },
  'css': {
    'dateRangePicker': $services.webjars.url('bootstrap-daterangepicker', 'css/bootstrap-daterangepicker.css'),
    'selectize': [
      $services.webjars.url('selectize.js', 'css/selectize.bootstrap3.css'),
      $xwiki.getSkinFile('uicomponents/suggest/xwiki.selectize.css', true)
    ]
  },
  'liveDataBasePath': $stringtool.removeEnd($liveDataPath, $liveDataEntry)
})
#[[*/
// Start JavaScript-only code.
(function(paths) {
  "use strict";

require.config({
  paths: paths.js,
  map: {
    '*': {
      daterangepicker: 'daterangepicker-with-css',
      'xwiki-selectize': 'xwiki-selectize-with-css'
    },
    'daterangepicker-with-css': {
      daterangepicker: 'daterangepicker'
    },
    'xwiki-selectize-with-css': {
      'xwiki-selectize': 'xwiki-selectize'
    }
  }
});

define('loadCSS', function() {
  var loadCSS = function(url) {
    var link = document.createElement("link");
    link.type = "text/css";
    link.rel = "stylesheet";
    link.href = url;
    document.getElementsByTagName("head")[0].appendChild(link);
  };

  return (url) => {
    var urls = Array.isArray(url) ? url : [url];
    urls.forEach(loadCSS);
  };
});

define('daterangepicker-with-css', ['loadCSS', 'daterangepicker'], function(loadCSS) {
  // Load the CSS for the date range picker.
  loadCSS(paths.css.dateRangePicker);
});

define('xwiki-selectize-with-css', ['loadCSS', 'xwiki-selectize'], function(loadCSS) {
  // Load the CSS for the suggest picker.
  loadCSS(paths.css.selectize);
});

window.liveDataBaseURL = paths.liveDataBasePath;

require(['jquery', 'Logic'], function($, LiveData) {
  $.fn.liveData = function(config) {
    return this.each(function() {
      if (!$(this).data('liveData')) {
        var instanceConfig = $.extend($(this).data('config'), config);
        $(this).attr('data-config', JSON.stringify(instanceConfig)).data('liveData', LiveData(this));
      }
    });
  };

  var init = function(event, data) {
    var container = $((data && data.elements) || document);
    container.find('.liveData').liveData();
  };

  $(document).on('xwiki:dom:updated', init);
  $(init);
});

// End JavaScript-only code.
}).apply(']]#', $jsontool.serialize([$paths]));

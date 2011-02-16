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
package org.xwiki.rendering.macro.dashboard;

import java.util.List;

import org.xwiki.component.annotation.ComponentRole;
import org.xwiki.rendering.transformation.MacroTransformationContext;

/**
 * Reads the gadgets for the dashboard macro which is being executed.
 * 
 * @version $Id$
 * @since 3.0M3
 */
@ComponentRole
public interface GadgetReader
{
    /**
     * Reads the gadgets for the passed macro transformation context.
     *
     * @param source the source to read dashboard gadgets from (a document serialized reference) 
     * @param context the dashboard macro transformation context
     * @return the list of gadgets for the currently executing macro
     * @throws Exception in case anything goes wrong reading data, the exception should be translated by the dashboard
     *             macro caller into a macro execution exception
     */
    List<Gadget> getGadgets(String source, MacroTransformationContext context) throws Exception;
}
